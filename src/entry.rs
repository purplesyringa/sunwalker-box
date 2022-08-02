use crate::{cgroups, mountns, procs, rootfs, sandbox, system, userns};
use anyhow::{bail, Context, Result};
use clap::{Args, Parser, Subcommand};
use multiprocessing::Object;
use nix::{
    libc,
    libc::{c_int, SYS_pidfd_open, PR_SET_PDEATHSIG, SIGUSR1},
    sys::{signal, wait},
};
use std::error::Error;
use std::ffi::CString;
use std::io::{BufRead, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::str::FromStr;
use std::sync::mpsc;
use std::time::{Duration, Instant};

fn parse_key_val<T, U>(s: &str) -> Result<(T, U), Box<dyn Error + Send + Sync>>
where
    T: FromStr,
    T::Err: Error + Send + Sync + 'static,
    U: FromStr,
    U::Err: Error + Send + Sync + 'static,
{
    let pos = s
        .find('=')
        .ok_or_else(|| format!("invalid KEY=value: no `=` found in `{}`", s))?;
    Ok((s[..pos].parse()?, s[pos + 1..].parse()?))
}

#[derive(Parser)]
#[clap(author, version, about, long_about = None)]
struct CLIArgs {
    #[clap(subcommand)]
    command: CLICommand,
}

#[derive(Subcommand)]
enum CLICommand {
    /// Isolates a CPU core so that a box can use it
    Isolate {
        /// CPU core number, 0-indexed
        #[clap(short, long)]
        core: u64,
    },

    /// Reverts CPU core isolation and returns it to the OS
    Free {
        /// CPU core number, 0-indexed
        #[clap(short, long)]
        core: u64,
    },

    /// Starts a new box
    Start(CLIStartCommand),
}

#[derive(Args, Object)]
struct CLIStartCommand {
    /// What core the box uses, 0-indexed
    #[clap(short, long)]
    core: u64,

    /// Directory to use as new root environment
    #[clap(short, long, default_value = "/", value_name = "PATH")]
    root: String,

    /// How much disk space the box may use
    #[clap(long, default_value_t = 32 * 1024 * 1024, value_name = "BYTES")]
    quota_space: u64,

    /// How many inodes the box may use
    #[clap(long, default_value_t = 1024, value_name = "INODES")]
    quota_inodes: u64,

    /// Environment variables
    #[clap(short = 'E', long, parse(try_from_str = parse_key_val), number_of_values = 1)]
    env: Vec<(String, String)>,

    /// (insecure) Don't abort preemptively if a non-CLOEXEC file descriptor is found. This should
    /// only be used for benchmarking.
    #[clap(long)]
    ignore_non_cloexec: bool,
}

#[derive(Object)]
enum Command {
    Reset,
    Run {
        argv: Vec<String>,
        stdin: String,
        stdout: String,
        stderr: String,
        real_time_limit: Option<Duration>,
        cpu_time_limit: Option<Duration>,
        idleness_time_limit: Option<Duration>,
        memory_limit: Option<usize>,
        processes_limit: Option<usize>,
    },
}

pub fn main() {
    let cli_args = CLIArgs::parse();

    sandbox::sanity_checks().expect("Sanity checks failed");

    match cli_args.command {
        CLICommand::Isolate { core } => {
            cgroups::Cgroup::new(core).expect("Failed to create cgroup for core");
        }
        CLICommand::Free { core } => {
            cgroups::revert_core_isolation(core).expect("Failed to core revert isolation");
        }
        CLICommand::Start(command) => {
            start(command).expect("Failed to start box");
        }
    }
}

fn start(cli_command: CLIStartCommand) -> Result<()> {
    let cgroup = cgroups::Cgroup::new(cli_command.core).context("Failed to create cgroup")?;

    // Move self to the right core so that spawning processes on the right core is fast. This also
    // has to be done before unsharing userns, as we'd then lose our root privileges, and moving
    // process from cgroup A to cgroup B requires write privileges in cgroup LCA(A, B) (according to
    // Linux source code; I don't think this is documented), and if we don't do it now, we won't be
    // able to do it later.
    cgroup
        .add_self_as_manager()
        .expect("Failed to add self to manager cgroup");

    // Our first priority is to unshare userns: we need to do before unsharing pidns (because /proc
    // can only be mounted if pidns was created inside the userns), therefore we need to do it in
    // this process.

    // Before unsharing userns, do whatever cannot be done inside the userns, namely, mount stuff.
    // Create an isolated mountns for a dedicated /tmp/sunwalker_box directory
    mountns::unshare_mountns().expect("Failed to unshare mount namespace");
    // Ensure our working area is ours only
    system::change_propagation("/", system::MS_PRIVATE | system::MS_REC)
        .expect("Failed to change propagation to private");
    // Create the dedicated /tmp/sunwalker_box
    sandbox::enter_working_area().expect("Failed to enter working area");
    // Create a copy of /dev
    sandbox::create_dev_copy().expect("Failed to create /dev copy");

    // Finally, unshare userns
    userns::enter_user_namespace().expect("Failed to unshare user namespace");
    // We need to synchronize mountns with userns, so it has to be remounted
    mountns::unshare_mountns().expect("Failed to unshare mount namespace");

    // Isolate various non-important namespaces
    sandbox::unshare_persistent_namespaces().expect("Failed to unshare persistent namespaces");

    // We need a separate worker to monitor the child (and no, using tokio won't work because then
    // using stdio would require a dedicated thread), but threads can't be created after unsharing
    // pidns, so we create the thread beforehand. We couldn't do this before because userns can't be
    // unshared in multithreaded processes.
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
        multiprocessing::duplex::<Command, std::result::Result<Option<String>, String>>()
            .context("Failed to create channel")?;

    let child = reaper
        .spawn(
            pidfd,
            cli_command,
            cgroup
                .try_clone()
                .context("Failed to clone cgroup reference")?,
            theirs,
        )
        .context("Failed to start child")?;
    thread_tx
        .send(child)
        .context("Failed to send child to thread")?;

    for line in std::io::BufReader::new(std::io::stdin()).lines() {
        let line = line.expect("Failed to read from stdin");
        let (command, arg) = line.split_once(' ').unwrap_or((&line, ""));
        let command = command.to_lowercase();
        match handle_command(&mut ours, &command, arg) {
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

    cgroup.destroy().context("Failed to destroy cgroup")?;

    Ok(())
}

fn handle_command(
    channel: &mut multiprocessing::Duplex<Command, std::result::Result<Option<String>, String>>,
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
        "reset" => Command::Reset,
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

            Command::Run {
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

extern "C" fn pid1_signal_handler(signo: c_int) {
    // std::process::exit is not async-safe
    unsafe {
        libc::_exit(128 + signo);
    }
}

#[multiprocessing::entrypoint]
fn reaper(
    ppidfd: OwnedFd,
    cli_command: CLIStartCommand,
    cgroup: cgroups::Cgroup,
    channel: multiprocessing::Duplex<std::result::Result<Option<String>, String>, Command>,
) -> ! {
    if nix::unistd::getpid().as_raw() != 1 {
        panic!("Reaper must have PID 1");
    }

    // We want to receive SIGUSR1 and SIGCHLD, but not handle them immediately
    let mut mask = signal::SigSet::empty();
    mask.add(signal::Signal::SIGUSR1);
    mask.add(signal::Signal::SIGCHLD);
    if let Err(e) = mask.thread_block() {
        eprintln!("Failed to configure signal mask: {e}");
        std::process::exit(1);
    }

    // PID 1 can't be killed, not even by suicide. Unfortunately, that's exactly what panic! does,
    // so every time panic! is called, it attempts to call abort(2), silently fails and gets stuck
    // in a SIGSEGV loop. That's not what we what, so we set handlers manually.
    for sig in [signal::Signal::SIGSEGV, signal::Signal::SIGABRT] {
        if let Err(e) = unsafe {
            signal::sigaction(
                sig,
                &signal::SigAction::new(
                    signal::SigHandler::Handler(pid1_signal_handler),
                    signal::SaFlags::empty(),
                    signal::SigSet::empty(),
                ),
            )
        } {
            eprintln!("Failed to configure sigaction: {e}");
            std::process::exit(1);
        }
    }

    // We want to terminate when parent dies
    if unsafe { libc::prctl(PR_SET_PDEATHSIG, SIGUSR1) } == -1 {
        panic!(
            "Failed to prctl(PR_SET_PDEATHSIG): {}",
            std::io::Error::last_os_error()
        );
    }
    // In the unlikely case when the parent terminated before or during prctl was called, check if
    // the parent is dead by now. pidfd_send_signal does not work across PID namespaces (not in this
    // case, anyway), so we have to resort to polling.
    if nix::poll::poll(
        &mut [nix::poll::PollFd::new(
            ppidfd.as_raw_fd(),
            nix::poll::PollFlags::POLLIN,
        )],
        0,
    )
    .expect("Failed to poll parent pidfd")
        != 0
    {
        std::process::exit(0);
    }

    if !cli_command.ignore_non_cloexec {
        // O_CLOEXEC is great and all, but better safe than sorry. We make sure all streams except
        // the standard ones are closed on exec.
        for entry in std::fs::read_dir("/proc/self/fd").expect("Failed to read /proc/self/fd") {
            let entry = entry.expect("Failed to read /proc/self/fd");
            let fd: RawFd = entry
                .file_name()
                .into_string()
                .expect("Invalid filename in /proc/self/fd")
                .parse()
                .expect("Invalid filename in /proc/self/fd");
            if fd < 3 {
                continue;
            }
            let flags = nix::fcntl::fcntl(fd, nix::fcntl::FcntlArg::F_GETFD)
                .expect("Failed to fcntl a file descriptor");
            if !nix::fcntl::FdFlag::from_bits_truncate(flags)
                .intersects(nix::fcntl::FdFlag::FD_CLOEXEC)
            {
                panic!("File descriptor {fd} is not CLOEXEC");
            }
        }
    }

    // We have to separate reaping and sandbox management, because we need to spawn processes, and
    // reaping all of them continuously is going to be confusing to stdlib.
    let mut child = manager
        .spawn(cli_command, cgroup, channel)
        .expect("Failed to start child");
    std::thread::spawn(move || {
        child.join().expect("Child failed");
    });

    'main: loop {
        let mut sigset = signal::SigSet::empty();
        sigset.add(signal::Signal::SIGUSR1);
        sigset.add(signal::Signal::SIGCHLD);
        match sigset.wait().expect("Failed to wait for signal") {
            signal::Signal::SIGUSR1 => {
                // Parent died
                break 'main;
            }
            signal::Signal::SIGCHLD => {
                // Child (or several) died
                loop {
                    match wait::waitpid(None, Some(wait::WaitPidFlag::WNOHANG)) {
                        Ok(res) => {
                            if res == wait::WaitStatus::StillAlive {
                                break;
                            }
                        }
                        Err(e) => {
                            if e == nix::errno::Errno::ECHILD {
                                // Manager terminated
                                break 'main;
                            } else {
                                panic!("Failed to waitpid: {e:?}");
                            }
                        }
                    }
                }
            }
            _ => {
                panic!("Unexpected signal");
            }
        }
    }

    // Don't send the result to the parent
    std::process::exit(0)
}

#[multiprocessing::entrypoint]
fn manager(
    cli_command: CLIStartCommand,
    cgroup: cgroups::Cgroup,
    mut channel: multiprocessing::Duplex<std::result::Result<Option<String>, String>, Command>,
) {
    // Setup rootfs. This has to happen inside the pidns, as we mount procfs here.
    let quotas = rootfs::DiskQuotas {
        space: cli_command.quota_space,
        max_inodes: cli_command.quota_inodes,
    };
    rootfs::enter_rootfs(cli_command.root.as_ref(), &quotas).expect("Failed to enter rootfs");
    std::env::set_current_dir("/space").expect("Failed to chdir to /space");

    while let Some(command) = channel
        .recv()
        .expect("Failed to receive message from channel")
    {
        channel
            .send(&match execute_command(command, &quotas, &cgroup) {
                Ok(value) => Ok(value),
                Err(e) => Err(format!("{e:?}")),
            })
            .expect("Failed to send reply to channel")
    }
}

fn execute_command(
    command: Command,
    quotas: &rootfs::DiskQuotas,
    cgroup: &cgroups::Cgroup,
) -> Result<Option<String>> {
    match command {
        Command::Reset => {
            std::env::set_current_dir("/").expect("Failed to chdir to /");
            rootfs::reset(quotas).context("Failed to reset rootfs")?;
            std::env::set_current_dir("/space").expect("Failed to chdir to /space");

            sandbox::reset_persistent_namespaces().context("Failed to persistent namespaces")?;

            procs::reset_pidns().context("Failed to reset pidns")?;

            // TODO: timens & rdtsc

            Ok(None)
        }
        Command::Run {
            argv,
            stdin,
            stdout,
            stderr,
            real_time_limit,
            cpu_time_limit,
            idleness_time_limit,
            memory_limit,
            processes_limit,
        } => {
            let stdin = std::fs::File::open(stdin).context("Failed to open stdin file")?;
            let stdout = std::fs::File::options()
                .write(true)
                .create(true)
                .open(stdout)
                .context("Failed to open stdout file")?;
            let stderr = std::fs::File::options()
                .write(true)
                .create(true)
                .open(stderr)
                .context("Failed to open stderr file")?;

            // Start process, redirecting standard streams and configuring ITIMER_PROF
            let (mut ours, theirs) =
                multiprocessing::duplex().context("Failed to create a pipe")?;
            let user_process = executor_worker
                .spawn(argv, stdin, stdout, stderr, theirs, cpu_time_limit)
                .context("Failed to spawn the child")?;
            let pid = user_process.id();

            // Acquire pidfd. This is safe because the process hasn't been awaited yet.
            let pidfd = unsafe { libc::syscall(SYS_pidfd_open, pid, 0) } as RawFd;
            if pidfd == -1 {
                return Err(std::io::Error::last_os_error())
                    .context("Failed to open pidfd for child process");
            }
            let pidfd = unsafe { OwnedFd::from_raw_fd(pidfd) };

            // Apply cgroup limits
            let user_cgroup = cgroup
                .create_user_cgroup()
                .context("Failed to create user cgroup")?;
            if let Some(memory_limit) = memory_limit {
                user_cgroup
                    .set_memory_limit(memory_limit)
                    .context("Failed to apply memory limit")?;
            }
            if let Some(processes_limit) = processes_limit {
                user_cgroup
                    .set_processes_limit(processes_limit)
                    .context("Failed to apply processes limit")?;
            }
            user_cgroup
                .add_process(pid)
                .context("Failed to move the child to user cgroup")?;

            let start_time = Instant::now();

            // Tell the child it's alright to start
            if ours.send(&()).is_err() {
                // This most likely indicates that the child has terminated before having a chance
                // to wait on the pipe, i.e. a preparation failure
                bail!(
                    "{}",
                    ours.recv()
                        .context("Failed to read an error from the child")?
                        .context(
                            "The child terminated preemptively but did not report any error"
                        )?
                );
            }

            // The child will either report an error during execve, or nothing if execve succeeded
            // and the pipe was closed automatically because it's CLOEXEC.
            if let Some(e) = ours
                .recv()
                .context("Failed to read an error from the child")?
            {
                bail!("{e:?}");
            }

            // Listen for events
            use nix::sys::epoll::*;
            let epollfd = epoll_create().context("Failed to create epollfd")?;
            let epollfd = unsafe { OwnedFd::from_raw_fd(epollfd) };
            epoll_ctl(
                epollfd.as_raw_fd(),
                EpollOp::EpollCtlAdd,
                pidfd.as_raw_fd(),
                &mut EpollEvent::new(EpollFlags::EPOLLIN, 0),
            )
            .context("Failed to configure epoll")?;

            let has_peak = user_cgroup.get_memory_peak()?.is_some();

            struct Metrics {
                real_time: Duration,
                cpu_time: Duration,
                idleness_time: Duration,
                memory: usize,
            }
            let mut metrics = Metrics {
                cpu_time: Duration::ZERO,
                real_time: Duration::ZERO,
                idleness_time: Duration::ZERO,
                memory: 0,
            };

            let mut exitted = false;

            loop {
                let cpu_stats = user_cgroup.get_cpu_stats()?;
                metrics.cpu_time = cpu_stats.total;
                metrics.real_time = start_time.elapsed();
                metrics.idleness_time = metrics.real_time.saturating_sub(metrics.cpu_time);
                if !has_peak {
                    metrics.memory = metrics.memory.max(user_cgroup.get_memory_total()?);
                }

                if exitted {
                    break;
                }

                // Check if any limits were exceeded
                if real_time_limit.is_some_and(|&limit| metrics.real_time > limit)
                    || cpu_time_limit.is_some_and(|&limit| metrics.cpu_time > limit)
                    || idleness_time_limit.is_some_and(|&limit| metrics.idleness_time > limit)
                    || memory_limit.is_some_and(|&limit| metrics.memory > limit)
                {
                    break;
                }

                let mut timeout = Duration::MAX;

                if let Some(real_time_limit) = real_time_limit {
                    timeout = timeout.min(real_time_limit - metrics.real_time);
                }

                // The connection between real time and CPU time is complicated. On the one hand, a
                // process can sleep, which does not count towards CPU time, so it can be as low as
                // it gets. Secondly, multithreaded applications can use several cores (TODO: add
                // opt-in support for that), and that means CPU time may exceed real time. The
                // inequality seems to be
                //     0 <= cpu_time <= real_time * n_cores,
                // so a process cannot exceed its CPU time limit during
                //     cpu_time_left / n_cores
                // seconds. This gives us a better way to handle TLE than by polling the stats every
                // few milliseconds. Instead, the algorithm is roughly (other limits
                // notwithstanding):
                //     while the process has not terminated and limits are not exceeded {
                //         let guaranteed_cpu_time_left = how much more CPU time the process can
                //             spend without exceeding the limit;
                //         let guaranteed_real_time_left = guaranteed_cpu_time_left / n_cores;
                //         sleep(guaranteed_real_time_left);
                //     }
                if let Some(cpu_time_limit) = cpu_time_limit {
                    timeout = timeout.min(cpu_time_limit - metrics.cpu_time);
                }

                // Similarly, a process cannot exceed its idleness time limit during
                // idleness_time_left seconds. It is not obvious how idleness time is to interact
                // with multicore programs, so ve should forbid the limit in this case (TODO).
                if let Some(idleness_time_limit) = idleness_time_limit {
                    timeout = timeout.min(idleness_time_limit - metrics.idleness_time);
                }

                // Old kernels don't reveal memory.peak, so the only way to get memory usage stats
                // is to use polling
                if !has_peak {
                    timeout = Duration::ZERO;
                }

                // Switching context takes time, some other operations take time too, etc., so less
                // CPU time is usually used than permitted. We also don't really want to interrupt
                // the process. We need to set a low limit on the timeout as well.
                //
                // In practice, adding 50ms seems like a good solution. This is not too big a number
                // to slow the judgment, not too small to steal resources from the solution in what
                // is effectively a spin lock, and allows SIGPROF to fire just at the right moment
                // under normal circumstances.
                if timeout != Duration::MAX {
                    timeout += Duration::from_millis(50);
                }

                let timeout_ms: i32 = if timeout == Duration::MAX {
                    -1
                } else {
                    // Old kernels don't support very large timeouts
                    timeout
                        .as_millis()
                        .try_into()
                        .unwrap_or(i32::MAX)
                        .min(1000000)
                };

                let mut events = [EpollEvent::empty()];
                let n_events = epoll_wait(epollfd.as_raw_fd(), &mut events, timeout_ms as isize)
                    .context("epoll_wait failed")?;

                match n_events {
                    0 => {
                        // End of allotted real time chunk, will check if the limits were exceeded
                        // on the next iteration of the loop
                    }
                    1 => {
                        // pidfd fired -- the process has terminated. We will exit on the next
                        // iteration, right after collecting metrics
                        exitted = true;
                    }
                    _ => {
                        return Err(std::io::Error::last_os_error())
                            .with_context(|| format!("epoll_wait returned {n_events}"));
                    }
                }
            }

            if has_peak {
                metrics.memory = metrics.memory.max(
                    user_cgroup
                        .get_memory_peak()?
                        .context("memory.peak is unexpectedly unavailable")?,
                );
            }

            let mut limit_verdict;
            if cpu_time_limit.is_some_and(|&limit| metrics.cpu_time > limit) {
                limit_verdict = "CPUTimeLimitExceeded";
            } else if real_time_limit.is_some_and(|&limit| metrics.real_time > limit) {
                limit_verdict = "RealTimeLimitExceeded";
            } else if idleness_time_limit.is_some_and(|&limit| metrics.idleness_time > limit) {
                limit_verdict = "IdlenessTimeLimitExceeded";
            } else if user_cgroup.was_oom_killed()?
                || memory_limit.is_some_and(|&limit| metrics.memory > limit)
            {
                limit_verdict = "MemoryLimitExceeded";
            } else {
                limit_verdict = "OK";
            }

            let mut exit_code: i32 = -1;

            if exitted {
                let wait_status = wait::waitpid(nix::unistd::Pid::from_raw(pid), None)
                    .context("Failed to waitpid for process")?;

                if let wait::WaitStatus::Signaled(_, signal::Signal::SIGPROF, _) = wait_status {
                    limit_verdict = "CPUTimeLimitExceeded";
                }
                if limit_verdict == "OK" {
                    match wait_status {
                        wait::WaitStatus::Exited(_, exit_code_) => {
                            exit_code = exit_code_;
                        }
                        wait::WaitStatus::Signaled(_, signal, _) => {
                            limit_verdict = "Signaled";
                            exit_code = signal as i32;
                        }
                        _ => {
                            bail!("waitpid returned unexpected status: {wait_status:?}");
                        }
                    }
                }
            } else {
                assert!(limit_verdict != "OK");
            }

            user_cgroup
                .destroy()
                .context("Failed to destroy user cgroup")?;

            Ok(Some(json::stringify(json::object! {
                limit_verdict: limit_verdict,
                exit_code: exit_code,
                real_time: metrics.real_time.as_secs_f64(),
                cpu_time: metrics.cpu_time.as_secs_f64(),
                idleness_time: metrics.idleness_time.as_secs_f64(),
                memory: metrics.memory,
            })))
        }
    }
}

#[multiprocessing::entrypoint]
fn executor_worker(
    argv: Vec<String>,
    stdin: std::fs::File,
    stdout: std::fs::File,
    stderr: std::fs::File,
    mut pipe: multiprocessing::Duplex<String, ()>,
    cpu_time_limit: Option<Duration>,
) {
    let result: Result<()> = try {
        userns::drop_privileges().context("Failed to drop privileges")?;

        nix::unistd::dup2(stdin.as_raw_fd(), nix::libc::STDIN_FILENO)
            .context("dup2 for stdin failed")?;
        nix::unistd::dup2(stdout.as_raw_fd(), nix::libc::STDOUT_FILENO)
            .context("dup2 for stdout failed")?;
        nix::unistd::dup2(stderr.as_raw_fd(), nix::libc::STDERR_FILENO)
            .context("dup2 for stderr failed")?;

        let is_absolute_path = argv[0].contains('/');

        let mut args = Vec::with_capacity(argv.len());
        for arg in argv {
            args.push(CString::new(arg.into_bytes()).context("Argument contains null character")?);
        }

        pipe.recv()
            .context("Failed to await confirmation from master process")?
            .context("No confirmation from master process")?;

        // Fine to start the application now. We don't need to reset signals because we didn't
        // configure them inside executor_worker()

        if let Some(cpu_time_limit) = cpu_time_limit {
            // An additional optimization for finer handling of cpu time limit. An ITIMER_PROF timer
            // can emit a signal when the given limit is exceeded and is not reset upon execve. This
            // only applies to a single process, not a cgroup, and can be overwritten by the user
            // program, but this feature is not mission-critical. It merely saves us a few precious
            // milliseconds due to the (somewhat artificially deliberate) inefficiency of polling.
            let timer = libc::itimerval {
                it_interval: libc::timeval {
                    tv_sec: 0,
                    tv_usec: 0,
                },
                it_value: libc::timeval {
                    tv_sec: cpu_time_limit.as_secs() as i64,
                    tv_usec: cpu_time_limit.subsec_micros() as i64,
                },
            };
            if unsafe {
                libc::syscall(
                    libc::SYS_setitimer,
                    libc::ITIMER_PROF,
                    &timer as *const libc::itimerval,
                    std::ptr::null_mut::<libc::itimerval>(),
                )
            } == -1
            {
                Err(std::io::Error::last_os_error()).context("Failed to set interval timer")?;
            }
        }

        if is_absolute_path {
            nix::unistd::execv(&args[0], &args).context("execv failed")?;
        } else {
            nix::unistd::execvp(&args[0], &args).context("execvp failed")?;
        }
    };

    if let Err(e) = result {
        pipe.send(&format!("{e:?}"))
            .expect("Failed to report error to parent");
    }
}
