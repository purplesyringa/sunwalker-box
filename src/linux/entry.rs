use crate::{
    entry,
    linux::{cgroups, manager, mountns, procs, reaper, rootfs, sandbox, system},
};
use anyhow::{anyhow, bail, Context, Result};
use nix::{libc, libc::SYS_pidfd_open};
use std::io::{BufRead, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::os::unix::io::{FromRawFd, OwnedFd, RawFd};
use std::sync::mpsc;
use std::time::Duration;

pub fn main(cli_args: entry::CLIArgs) {
    sandbox::sanity_checks().expect("Sanity checks failed");

    match cli_args.command {
        entry::CLICommand::Isolate { core } => {
            cgroups::Cgroup::new(core).expect("Failed to create cgroup for core");
        }
        entry::CLICommand::Free { core } => {
            cgroups::revert_core_isolation(core).expect("Failed to core revert isolation");
        }
        entry::CLICommand::Start(command) => {
            start(command).expect("Failed to start box");
        }
    }
}

fn start(cli_command: entry::CLIStartCommand) -> Result<()> {
    let cgroup = cgroups::Cgroup::new(cli_command.core).context("Failed to create cgroup")?;

    // Move self to the right core so that spawning processes on the right core is fast. This also
    // has to be done before unsharing userns, as we'd then lose our root privileges, and moving
    // process from cgroup A to cgroup B requires write privileges in cgroup LCA(A, B), and if we
    // don't do it now, we won't be able to do it later.
    cgroup
        .add_self_as_manager()
        .expect("Failed to add self to manager cgroup");

    let root =
        std::fs::canonicalize(&cli_command.root).context("Failed to resolve path to root")?;

    // Do whatever cannot be done inside the userns. This mostly amounts to mounting stuff.
    // Create an isolated mountns for a dedicated /tmp/sunwalker_box directory
    mountns::unshare_mountns().expect("Failed to unshare mount namespace");
    // Ensure our working area is ours only
    system::change_propagation("/", system::MS_PRIVATE | system::MS_REC)
        .expect("Failed to change propagation to private");
    // Create the dedicated /tmp/sunwalker_box
    sandbox::enter_working_area().expect("Failed to enter working area");
    // Create a copy of /dev
    sandbox::create_dev_copy().expect("Failed to create /dev copy");

    // Isolate various non-important namespaces
    sandbox::unshare_persistent_namespaces().expect("Failed to unshare persistent namespaces");

    // We need a separate worker to monitor the child (and no, using tokio won't work because then
    // using stdio would require a dedicated thread), but threads can't be created after unsharing
    // pidns, so we create the thread beforehand.
    let (thread_tx, thread_rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut child: multiprocessing::Child<!> =
            thread_rx.recv().expect("Failed to receive child in thread");
        panic!("Child failed: {}", child.join().into_err());
    });

    // Run a child in a new PID namespace
    procs::unshare_pidns().context("Failed to unshare pid namespace")?;

    // Recreate environment, exposing reasonable defaults
    for (key, _) in std::env::vars_os() {
        std::env::remove_var(key);
    }
    std::env::set_var(
        "LD_LIBRARY_PATH",
        "/usr/local/lib64:/usr/local/lib:/usr/lib64:/usr/lib:/lib64:/lib",
    );
    std::env::set_var("LANGUAGE", "en_US");
    std::env::set_var("LC_ALL", "en_US.UTF-8");
    std::env::set_var("LC_ADDRESS", "en_US.UTF-8");
    std::env::set_var("LC_NAME", "en_US.UTF-8");
    std::env::set_var("LC_MONETARY", "en_US.UTF-8");
    std::env::set_var("LC_PAPER", "en_US.UTF-8");
    std::env::set_var("LC_IDENTIFIER", "en_US.UTF-8");
    std::env::set_var("LC_TELEPHONE", "en_US.UTF-8");
    std::env::set_var("LC_MEASUREMENT", "en_US.UTF-8");
    std::env::set_var("LC_TIME", "en_US.UTF-8");
    std::env::set_var("LC_NUMERIC", "en_US.UTF-8");
    std::env::set_var("LANG", "en_US.UTF-8");
    for (key, value) in &cli_command.env {
        std::env::set_var(key, value);
    }

    // We need to pass a reference to ourselves to the child for monitoring, but cross-pid-namespace
    // communication doesn't work well, so we use pidfd. As a side note, pidfd_open sets O_CLOEXEC
    // automatically.
    let pidfd = unsafe { libc::syscall(SYS_pidfd_open, nix::unistd::getpid(), 0) } as RawFd;
    if pidfd == -1 {
        panic!(
            "Failed to get pidfd of self: {}",
            std::io::Error::last_os_error()
        );
    }
    let pidfd = unsafe { OwnedFd::from_raw_fd(pidfd) };

    let (mut ours, theirs) =
        multiprocessing::duplex::<manager::Command, std::result::Result<Option<String>, String>>()
            .context("Failed to create channel")?;

    // Setup rootfs
    let mut root_cur = std::path::PathBuf::from("/oldroot");
    root_cur.extend(root.strip_prefix("/"));
    rootfs::create_rootfs(&root_cur).expect("Failed to create rootfs");

    let quotas = rootfs::DiskQuotas {
        space: cli_command.quota_space,
        max_inodes: cli_command.quota_inodes,
    };

    let child = reaper::reaper
        .spawn(pidfd, cli_command, cgroup, theirs)
        .context("Failed to start child")?;
    thread_tx
        .send(child)
        .context("Failed to send child to thread")?;

    ours.recv()
        .context("Failed to recv readiness signal")?
        .context("Manager terminated too early")?
        .map_err(|e| anyhow!("Manager reported error during startup: {e}"))?;

    rootfs::reset(&quotas).expect("Failed to reset rootfs");

    for line in std::io::BufReader::new(std::io::stdin()).lines() {
        let line = line.expect("Failed to read from stdin");
        let (command, arg) = line.split_once(' ').unwrap_or((&line, ""));
        let command = command.to_lowercase();
        match handle_command(&mut ours, &quotas, &command, arg) {
            Ok(None) => {
                println!("ok");
            }
            Ok(Some(s)) => {
                println!("ok {s}");
            }
            Err(e) => {
                println!("error {}", json::stringify(format!("{e:?}")));
            }
        }
    }

    Ok(())
}

fn handle_command(
    channel: &mut multiprocessing::Duplex<
        manager::Command,
        std::result::Result<Option<String>, String>,
    >,
    quotas: &rootfs::DiskQuotas,
    command: &str,
    arg: &str,
) -> Result<Option<String>> {
    let sent_command = match command {
        "mkdir" => {
            let path = json::parse(arg)
                .context("Invalid JSON")?
                .take_string()
                .context("Invalid command argument")?;
            std::fs::create_dir(rootfs::resolve_abs_box_root(path)?)?;
            return Ok(None);
        }
        "ls" => {
            let path = json::parse(arg)
                .context("Invalid JSON")?
                .take_string()
                .context("Invalid command argument")?;
            let mut entries = json::object! {};
            for entry in std::fs::read_dir(rootfs::resolve_abs_box_root(path)?)? {
                let entry = entry?;
                let file_name = entry
                    .file_name()
                    .into_string()
                    .or_else(|name| bail!("Invalid file name: {name:?}"))?;
                let metadata = entry.metadata()?;
                let file_type = metadata.file_type();
                let permissions = metadata.permissions();
                entries[file_name] = json::object! {
                    file_type: if file_type.is_dir() {
                        "dir"
                    } else if file_type.is_file() {
                        "file"
                    } else if file_type.is_symlink() {
                        "symlink"
                    } else if file_type.is_block_device() {
                        "block"
                    } else if file_type.is_char_device() {
                        "char"
                    } else if file_type.is_fifo() {
                        "fifo"
                    } else if file_type.is_socket() {
                        "socket"
                    } else {
                        "unknown"
                    },
                    len: metadata.len(),
                    mode: permissions.mode(),
                };
            }
            return Ok(Some(entries.dump()));
        }
        "cat" => {
            let mut arg = json::parse(arg).context("Invalid JSON")?;
            let (path, at, len);
            if arg.is_string() {
                path = arg.take_string().unwrap();
                at = 0;
                len = 0;
            } else {
                path = arg["path"]
                    .take_string()
                    .context("Invalid 'path' argument")?;
                at = arg["at"].as_usize().context("Invalid 'at' argument")?;
                len = arg["len"].as_usize().context("Invalid 'len' argument")?;
            }

            let mut file = std::fs::File::open(rootfs::resolve_abs_box_root(path)?)
                .context("Failed to open file")?;
            let metadata = file.metadata().context("Failed to read metadata")?;
            if !metadata.is_file() {
                bail!("The passed path does not refer to a regular file");
            }
            let file_len = metadata.len().try_into().context("Too big file")?;
            if at > file_len {
                bail!("Offset after end of file");
            }
            let mut read_len = file_len - at;
            if len != 0 {
                read_len = read_len.min(len);
            }
            file.seek(SeekFrom::Start(at as u64))
                .context("Failed to seek")?;
            let mut buf = vec![0u8; read_len];
            let mut ptr: usize = 0;
            while ptr < read_len {
                let n_read = file.read(&mut buf[ptr..])?;
                if n_read == 0 {
                    break;
                }
                ptr += n_read;
            }
            buf.truncate(ptr);
            return Ok(Some(json::stringify(buf)));
        }
        "mkfile" => {
            let mut arg = json::parse(arg).context("Invalid JSON")?;
            let path = arg["path"]
                .take_string()
                .context("Invalid 'path' argument")?;
            let mut content;
            match &arg["content"] {
                json::JsonValue::Array(arr) => {
                    content = Vec::with_capacity(arr.len());
                    for elem in arr {
                        content.push(elem.as_u8().context("Invalid 'content' argument")?);
                    }
                }
                _ => bail!("Invalid 'content' argument"),
            };

            let mut file = std::fs::File::create(rootfs::resolve_abs_box_root(path)?)?;
            file.write_all(&content)?;
            return Ok(None);
        }
        "mksymlink" => {
            let mut arg = json::parse(arg).context("Invalid JSON")?;
            let link = arg["link"]
                .take_string()
                .context("Invalid 'link' argument")?;
            let target = arg["target"]
                .take_string()
                .context("Invalid 'target' argument")?;
            std::os::unix::fs::symlink(target, rootfs::resolve_abs_box_root(link)?)?;
            return Ok(None);
        }
        "bind" => {
            let mut arg = json::parse(arg).context("Invalid JSON")?;
            let external = arg["external"]
                .take_string()
                .context("Invalid 'external' argument")?;
            let internal = arg["internal"]
                .take_string()
                .context("Invalid 'internal' argument")?;
            let ro = arg["ro"].as_bool().context("Invalid 'ro' argument")?;
            system::bind_mount_opt(
                rootfs::resolve_abs_old_root(external)?,
                rootfs::resolve_abs_box_root(internal)?,
                if ro { system::MS_RDONLY } else { 0 } | system::MS_REC,
            )?;
            return Ok(None);
        }
        "reset" => {
            sandbox::reset_persistent_namespaces().context("Failed to persistent namespaces")?;
            rootfs::reset(quotas).context("Failed to reset rootfs")?;
            procs::reset_pidns().context("Failed to reset pidns")?;

            // TODO: timens & rdtsc

            manager::Command::Reset
        }
        "run" => {
            let mut arg = json::parse(arg).context("Invalid JSON")?;
            if !arg["argv"].is_array() {
                bail!("Invalid 'argv' argument");
            }

            let mut argv = Vec::with_capacity(arg["argv"].len());
            for arg in arg["argv"].members_mut() {
                argv.push(arg.take_string().context("Invalid 'argv' argument")?);
            }
            if argv.is_empty() {
                bail!("'argv' is empty");
            }

            let stdin = if arg["stdin"].is_null() {
                "/dev/null".to_string()
            } else {
                arg["stdin"]
                    .take_string()
                    .context("Invalid 'stdin' argument")?
            };
            let stdout = if arg["stdout"].is_null() {
                "/dev/null".to_string()
            } else {
                arg["stdout"]
                    .take_string()
                    .context("Invalid 'stdout' argument")?
            };
            let stderr = if arg["stderr"].is_null() {
                "/dev/null".to_string()
            } else {
                arg["stderr"]
                    .take_string()
                    .context("Invalid 'stderr' argument")?
            };

            let real_time_limit = if arg["real_time_limit"].is_null() {
                None
            } else {
                Some(Duration::from_secs_f64(
                    arg["real_time_limit"]
                        .as_f64()
                        .context("Invalid 'real_time_limit' argument")?,
                ))
            };
            let cpu_time_limit = if arg["cpu_time_limit"].is_null() {
                None
            } else {
                Some(Duration::from_secs_f64(
                    arg["cpu_time_limit"]
                        .as_f64()
                        .context("Invalid 'cpu_time_limit' argument")?,
                ))
            };
            let idleness_time_limit = if arg["idleness_time_limit"].is_null() {
                None
            } else {
                Some(Duration::from_secs_f64(
                    arg["idleness_time_limit"]
                        .as_f64()
                        .context("Invalid 'idleness_time_limit' argument")?,
                ))
            };
            let memory_limit = if arg["memory_limit"].is_null() {
                None
            } else {
                Some(
                    arg["memory_limit"]
                        .as_usize()
                        .context("Invalid 'memory_limit' argument")?,
                )
            };
            let processes_limit = if arg["processes_limit"].is_null() {
                None
            } else {
                Some(
                    arg["processes_limit"]
                        .as_usize()
                        .context("Invalid 'processes_limit' argument")?,
                )
            };

            manager::Command::Run {
                argv,
                stdin,
                stdout,
                stderr,
                real_time_limit,
                cpu_time_limit,
                idleness_time_limit,
                memory_limit,
                processes_limit,
            }
        }
        _ => {
            bail!("Unknown command {command}");
        }
    };

    channel
        .send(&sent_command)
        .context("Failed to send command")?;

    match channel.recv().context("Failed to recv reply")? {
        None => bail!("No reply from child"),
        Some(Ok(value)) => Ok(value),
        Some(Err(e)) => bail!("{e}"),
    }
}
