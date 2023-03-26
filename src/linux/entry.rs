use crate::{
    entry,
    linux::{cgroups, controller, manager, rootfs, running, sandbox},
};
use anyhow::{bail, Context, Result};
use std::collections::HashMap;
use std::io::{BufRead, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::time::Duration;

pub fn main(cli_args: entry::CLIArgs) {
    sandbox::sanity_checks().expect("Sanity checks failed");

    match cli_args.command {
        entry::CLICommand::Isolate(command) => {
            cgroups::Cgroup::new(command.core).expect("Failed to create cgroup for core");
        }
        entry::CLICommand::Free(command) => {
            cgroups::revert_core_isolation(command.core).expect("Failed to core revert isolation");
        }
        entry::CLICommand::Start(command) => {
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
            let path = json::parse(arg)
                .context("Invalid JSON")?
                .take_string()
                .context("Invalid command argument")?;
            let path = rootfs::resolve_abs_box_root(path)?;
            controller.ensure_allowed_to_modify(&path)?;
            std::fs::create_dir(path)?;
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
            let path = rootfs::resolve_abs_box_root(path)?;
            controller.ensure_allowed_to_modify(&path)?;
            let mut file = std::fs::File::create(path)?;
            file.write_all(&content)?;
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

            let mut env = None;
            if !arg["env"].is_null() {
                let mut env1 = HashMap::with_capacity(arg["env"].len());
                for (key, value) in arg["env"].entries_mut() {
                    env1.insert(
                        key.to_string(),
                        value.take_string().context("Invalid 'env' argument")?,
                    );
                }
                env = Some(env1);
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
