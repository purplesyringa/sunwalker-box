use crate::{
    entry,
    linux::{cgroups, controller, ids, kmodule, manager, rootfs, running, sandbox},
};
use anyhow::{bail, ensure, Context, Result};
use nix::libc::mode_t;
use std::io::{BufRead, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::time::Duration;

pub fn main(cli_args: entry::CLIArgs) {
    sandbox::sanity_checks().expect("Sanity checks failed");

    match cli_args.command {
        entry::CLICommand::Isolate(command) => {
            kmodule::install().expect("Failed to install kernel module");
            cgroups::Cgroup::new(command.core).expect("Failed to create cgroup for core");
        }
        entry::CLICommand::Free(command) => {
            cgroups::revert_core_isolation(command.core).expect("Failed to core revert isolation");
        }
        entry::CLICommand::Start(command) => {
            kmodule::install().expect("Failed to install kernel module");
            start(command).expect("Failed to start box");
        }
    }
}

fn start(cli_command: entry::CLIStartCommand) -> Result<()> {
    let quotas = rootfs::DiskQuotas {
        space: cli_command.quota_space,
        max_inodes: cli_command.quota_inodes,
    };

    let mut controller = controller::Controller::try_new(quotas)?;
    controller.join_core(cli_command.core)?;
    controller.enter_root(cli_command.root.as_ref())?;
    controller.start(cli_command)?;

    for line in std::io::BufReader::new(std::io::stdin()).lines() {
        let line = line.context("Failed to read from stdin")?;
        let (command, arg) = line.split_once(' ').unwrap_or((&line, ""));
        let command = command.to_lowercase();
        match handle_command(&mut controller, &command, arg) {
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
    controller: &mut controller::Controller,
    command: &str,
    arg: &str,
) -> Result<Option<String>> {
    match command {
        "mkdir" => {
            let (path, owner, mode);
            let mut arg = json::parse(arg).context("Invalid JSON")?;
            if arg.is_string() {
                path = arg.take_string().unwrap();
                owner = "root";
                mode = 0o755;
            } else {
                path = arg["path"]
                    .take_string()
                    .context("Invalid 'path' argument")?;
                owner = if arg["owner"].is_null() {
                    "root"
                } else {
                    arg["owner"].as_str().context("Invalid 'owner' argument")?
                };
                mode = if arg["mode"].is_null() {
                    0o755
                } else {
                    arg["mode"].as_u32().context("Invalid 'mode' argument")?
                };
            }
            let path = rootfs::resolve_abs_box_root(path)?;
            controller.ensure_allowed_to_modify(&path)?;
            std::fs::create_dir(&path)?;
            fix_permissions(&path, owner, mode)?;
            Ok(None)
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
            Ok(Some(entries.dump()))
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
            if file_len == 0 && len == 0 && at == 0 {
                // Might be a special file
                let mut buf = vec![];
                file.read_to_end(&mut buf)?;
                return Ok(Some(json::stringify(buf)));
            }
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
            Ok(Some(json::stringify(buf)))
        }
        "extpath" => {
            let path = json::parse(arg)
                .context("Invalid JSON")?
                .take_string()
                .context("Invalid command argument")?;
            let path = rootfs::resolve_abs_box_root(path)?;
            let pid = std::process::id();
            let system_path = format!(
                "/proc/{pid}/root{}",
                path.to_str().context("Path is not UTF-8")?
            );
            Ok(Some(json::stringify(system_path)))
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
            let owner = if arg["owner"].is_null() {
                "root"
            } else {
                arg["owner"].as_str().context("Invalid 'owner' argument")?
            };
            let mode = if arg["mode"].is_null() {
                0o644
            } else {
                arg["mode"].as_u32().context("Invalid 'mode' argument")?
            };
            let path = rootfs::resolve_abs_box_root(path)?;
            controller.ensure_allowed_to_modify(&path)?;
            let mut file = std::fs::File::create(&path)?;
            file.write_all(&content)?;
            fix_permissions(&path, owner, mode)?;
            Ok(None)
        }
        "mksymlink" => {
            let mut arg = json::parse(arg).context("Invalid JSON")?;
            let link = arg["link"]
                .take_string()
                .context("Invalid 'link' argument")?;
            let target = arg["target"]
                .take_string()
                .context("Invalid 'target' argument")?;
            let link = rootfs::resolve_abs_box_root(link)?;
            controller.ensure_allowed_to_modify(&link)?;
            std::os::unix::fs::symlink(target, link)?;
            Ok(None)
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
            controller.bind(&external, &internal, ro)?;
            Ok(None)
        }
        "reset" => {
            controller.reset()?;
            Ok(None)
        }
        "commit" => {
            controller.commit()?;
            Ok(None)
        }
        "run" => {
            let mut arg = json::parse(arg).context("Invalid JSON")?;

            let argv = arg["argv"]
                .members_mut()
                .map(|arg| arg.take_string())
                .collect::<Option<Vec<_>>>()
                .context("Invalid 'argv' argument")?;
            ensure!(!argv.is_empty(), "'argv' is empty");

            let mut parse_string = |name: &str| -> Result<Option<String>> {
                Ok(if arg[name].is_null() {
                    None
                } else {
                    Some(
                        arg[name]
                            .take_string()
                            .with_context(|| format!("Invalid '{name}' argument"))?,
                    )
                })
            };
            let stdin = parse_string("stdin")?.unwrap_or_else(|| "/dev/null".to_string());
            let stdout = parse_string("stdout")?.unwrap_or_else(|| "/dev/null".to_string());
            let stderr = parse_string("stderr")?.unwrap_or_else(|| "/dev/null".to_string());

            let parse_duration = |name: &str| -> Result<Option<Duration>> {
                if arg[name].is_null() {
                    Ok(None)
                } else {
                    Ok(Some(Duration::from_secs_f64(
                        arg[name]
                            .as_f64()
                            .with_context(|| format!("Invalid '{name}' argument"))?,
                    )))
                }
            };
            let real_time_limit = parse_duration("real_time_limit")?;
            let cpu_time_limit = parse_duration("cpu_time_limit")?;
            let idleness_time_limit = parse_duration("idleness_time_limit")?;

            let parse_usize = |name: &str| -> Result<Option<usize>> {
                if arg[name].is_null() {
                    Ok(None)
                } else {
                    Ok(Some(
                        arg[name]
                            .as_usize()
                            .with_context(|| format!("Invalid '{name}' argument"))?,
                    ))
                }
            };
            let memory_limit = parse_usize("memory_limit")?;
            let processes_limit = parse_usize("processes_limit")?;

            let mut env = None;
            if !arg["env"].is_null() {
                env = Some(
                    arg["env"]
                        .entries_mut()
                        .map(|(key, value)| Some((key.to_string(), value.take_string()?)))
                        .collect::<Option<_>>()
                        .context("Invalid 'env' argument")?,
                );
            }

            controller.run_manager_command(manager::Command::Run {
                options: running::Options {
                    argv,
                    stdin,
                    stdout,
                    stderr,
                    real_time_limit,
                    cpu_time_limit,
                    idleness_time_limit,
                    memory_limit,
                    processes_limit,
                    env,
                },
            })
        }
        _ => {
            bail!("Unknown command {command}");
        }
    }
}

fn fix_permissions(path: &std::path::Path, owner: &str, mode: mode_t) -> Result<()> {
    let (uid, gid) = match owner {
        "user" => (ids::EXTERNAL_USER_UID, ids::EXTERNAL_USER_GID),
        "root" => (ids::EXTERNAL_ROOT_UID, ids::EXTERNAL_ROOT_GID),
        _ => bail!("Invalid owner {owner}"),
    };
    std::os::unix::fs::chown(path, Some(uid), Some(gid))
        .with_context(|| format!("Failed to chown {path:?}"))?;
    std::fs::set_permissions(path, std::os::unix::fs::PermissionsExt::from_mode(mode))
        .with_context(|| format!("Failed to chmod {path:?}"))?;
    Ok(())
}
