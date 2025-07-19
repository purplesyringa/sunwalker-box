use crate::{
    entry,
    linux::{cgroups, controller, ids, kmodule, manager, rootfs, running, sandbox},
    log,
    log::LogLevel,
};
use anyhow::{anyhow, bail, ensure, Context, Result};
use miniserde::{json, Deserialize, Serialize};
use nix::libc::mode_t;
use std::collections::HashMap;
use std::fs;
use std::fs::File;
use std::io;
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::os::unix::{
    fs as unix_fs,
    fs::{FileTypeExt, PermissionsExt},
};
use std::path::Path;
use std::process;
use std::time::Duration;

pub fn main(cli_args: entry::CLIArgs) -> Result<()> {
    let log_level = cli_args
        .log_level
        .or_else(|| std::env::var("SUNWALKER_BOX_LOG").ok());
    let log_level = log_level.as_deref().unwrap_or("none");
    let log_level = match log_level {
        "notice" => LogLevel::Notice,
        "warn" => LogLevel::Warn,
        "impossible" => LogLevel::Impossible,
        "none" => LogLevel::None,
        _ => bail!("Unknown log level {log_level}"),
    };
    log::enable_diagnostics("main", log_level);

    sandbox::sanity_checks().context("Sanity checks failed")?;

    match cli_args.command {
        entry::CLICommand::Isolate(command) => {
            kmodule::install().context("Failed to install kernel module")?;
            cgroups::Cgroup::new(command.core).context("Failed to create cgroup for core")?;
        }
        entry::CLICommand::Free(command) => {
            cgroups::revert_core_isolation(command.core)
                .context("Failed to core revert isolation")?;
        }
        entry::CLICommand::Start(command) => {
            kmodule::install().context("Failed to install kernel module")?;
            start(command).context("Failed to start box")?;
        }
    }

    Ok(())
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

    for line in BufReader::new(io::stdin()).lines() {
        let line = line.context("Failed to read from stdin")?;
        let (command, arg) = line.split_once(' ').unwrap_or((&line, ""));
        match handle_command(&mut controller, command, arg) {
            Ok(None) => {
                println!("ok");
            }
            Ok(Some(s)) => {
                println!("ok {s}");
            }
            Err(e) => {
                println!("error {}", json::to_string(&format!("{e:?}")));
            }
        }
    }

    log!("Terminating");
    Ok(())
}

trait CliCommand {
    fn execute(self, controller: &mut controller::Controller) -> Result<Option<String>>;
}

#[derive(Deserialize)]
struct Mkdir {
    path: String,
    owner: Option<String>,
    mode: Option<mode_t>,
}

impl CliCommand for Mkdir {
    fn execute(self, controller: &mut controller::Controller) -> Result<Option<String>> {
        let path = rootfs::resolve_abs_box_root(&self.path)?;
        controller.ensure_allowed_to_modify(&path)?;
        fs::create_dir(&path)?;
        fix_permissions(
            &path,
            self.owner.as_deref().unwrap_or("root"),
            self.mode.unwrap_or(0o755),
        )?;
        Ok(None)
    }
}

#[derive(Deserialize)]
struct Ls {
    path: String,
}

#[derive(Serialize)]
struct LsEntryMetadata {
    file_type: &'static str,
    len: u64,
    mode: mode_t,
}

impl CliCommand for Ls {
    fn execute(self, _controller: &mut controller::Controller) -> Result<Option<String>> {
        let mut entries = HashMap::new();
        for entry in fs::read_dir(rootfs::resolve_abs_box_root(self.path)?)? {
            let entry = entry?;
            let file_name = entry
                .file_name()
                .into_string()
                .map_err(|name| anyhow!("Invalid file name: {name:?}"))?;
            let metadata = entry.metadata()?;
            let file_type = metadata.file_type();
            let permissions = metadata.permissions();
            entries
                .insert(
                    file_name,
                    LsEntryMetadata {
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
                    },
                );
        }
        Ok(Some(json::to_string(&entries)))
    }
}

#[derive(Deserialize)]
struct Cat {
    path: String,
    at: Option<usize>,
    len: Option<usize>,
}

impl CliCommand for Cat {
    fn execute(self, _controller: &mut controller::Controller) -> Result<Option<String>> {
        let mut file =
            File::open(rootfs::resolve_abs_box_root(&self.path)?).context("Failed to open file")?;
        let metadata = file.metadata().context("Failed to read metadata")?;
        ensure!(
            metadata.is_file(),
            "The passed path does not refer to a regular file"
        );

        let len = self.len.unwrap_or(0);
        let at = self.at.unwrap_or(0);

        let file_len = metadata.len().try_into().context("Too big file")?;
        if file_len == 0 && len == 0 && at == 0 {
            // Might be a special file
            let mut buf = vec![];
            file.read_to_end(&mut buf)?;
            return Ok(Some(json::to_string(&buf)));
        }

        ensure!(at <= file_len, "Offset after end of file");
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

        Ok(Some(json::to_string(&buf)))
    }
}

#[derive(Deserialize)]
struct Extpath {
    path: String,
}

impl CliCommand for Extpath {
    fn execute(self, _controller: &mut controller::Controller) -> Result<Option<String>> {
        let path = rootfs::resolve_abs_box_root(self.path)?;
        let pid = process::id();
        let system_path = format!(
            "/proc/{pid}/root{}",
            path.to_str().context("Path is not UTF-8")?
        );
        Ok(Some(json::to_string(&system_path)))
    }
}

#[derive(Deserialize)]
struct Mkfile {
    path: String,
    content: Vec<u8>,
    owner: Option<String>,
    mode: Option<mode_t>,
}

impl CliCommand for Mkfile {
    fn execute(self, controller: &mut controller::Controller) -> Result<Option<String>> {
        let path = rootfs::resolve_abs_box_root(&self.path)?;
        controller.ensure_allowed_to_modify(&path)?;
        let mut file = File::create(&path)?;
        file.write_all(&self.content)?;
        fix_permissions(
            &path,
            self.owner.as_deref().unwrap_or("root"),
            self.mode.unwrap_or(0o644),
        )?;
        Ok(None)
    }
}

#[derive(Deserialize)]
struct Mksymlink {
    link: String,
    target: String,
}

impl CliCommand for Mksymlink {
    fn execute(self, controller: &mut controller::Controller) -> Result<Option<String>> {
        let link = rootfs::resolve_abs_box_root(&self.link)?;
        controller.ensure_allowed_to_modify(&link)?;
        unix_fs::symlink(&self.target, link)?;
        Ok(None)
    }
}

#[derive(Deserialize)]
struct Bind {
    external: String,
    internal: String,

    // This is plain cringe.
    ro: bool,
}

impl CliCommand for Bind {
    fn execute(self, controller: &mut controller::Controller) -> Result<Option<String>> {
        controller.bind(&self.external, &self.internal, self.ro)?;
        Ok(None)
    }
}

struct Reset;

impl CliCommand for Reset {
    fn execute(self, controller: &mut controller::Controller) -> Result<Option<String>> {
        controller.reset()?;
        Ok(None)
    }
}

struct Commit;

impl CliCommand for Commit {
    fn execute(self, controller: &mut controller::Controller) -> Result<Option<String>> {
        controller.commit()?;
        Ok(None)
    }
}

#[derive(Deserialize)]
struct Run {
    argv: Vec<String>,
    stdin: Option<String>,
    stdout: Option<String>,
    stderr: Option<String>,
    real_time_limit: Option<f64>,
    cpu_time_limit: Option<f64>,
    idleness_time_limit: Option<f64>,
    memory_limit: Option<usize>,
    processes_limit: Option<usize>,
    env: Option<HashMap<String, String>>,
}

impl CliCommand for Run {
    fn execute(self, controller: &mut controller::Controller) -> Result<Option<String>> {
        ensure!(!self.argv.is_empty(), "argv must not be empty");
        let dev_null = || "/dev/null".to_owned();

        controller.run_manager_command(manager::Command::Run {
            options: running::Options {
                argv: self.argv,
                stdin: self.stdin.unwrap_or_else(dev_null),
                stdout: self.stdout.unwrap_or_else(dev_null),
                stderr: self.stderr.unwrap_or_else(dev_null),
                real_time_limit: self.real_time_limit.map(Duration::from_secs_f64),
                cpu_time_limit: self.cpu_time_limit.map(Duration::from_secs_f64),
                idleness_time_limit: self.idleness_time_limit.map(Duration::from_secs_f64),
                memory_limit: self.memory_limit,
                processes_limit: self.processes_limit,
                env: self.env,
            },
        })
    }
}

fn handle_command(
    controller: &mut controller::Controller,
    command: &str,
    arg: &str,
) -> Result<Option<String>> {
    match command {
        "mkdir" => CliCommand::execute(
            if let Ok(path) = json::from_str(arg) {
                Mkdir {
                    path,
                    owner: None,
                    mode: None,
                }
            } else {
                json::from_str(arg).context("Invalid JSON")?
            },
            controller,
        ),
        "ls" => CliCommand::execute(
            Ls {
                path: json::from_str(arg).context("Invalid JSON")?,
            },
            controller,
        ),
        "cat" => CliCommand::execute(
            if let Ok(path) = json::from_str(arg) {
                Cat {
                    path,
                    at: None,
                    len: None,
                }
            } else {
                json::from_str(arg).context("Invalid JSON")?
            },
            controller,
        ),
        "extpath" => CliCommand::execute(
            Extpath {
                path: if arg.is_empty() {
                    "/".into()
                } else {
                    json::from_str(arg).context("Invalid JSON")?
                },
            },
            controller,
        ),
        "mkfile" => CliCommand::execute(
            json::from_str::<Mkfile>(arg).context("Invalid JSON")?,
            controller,
        ),
        "mksymlink" => CliCommand::execute(
            json::from_str::<Mksymlink>(arg).context("Invalid JSON")?,
            controller,
        ),
        "bind" => CliCommand::execute(
            json::from_str::<Bind>(arg).context("Invalid JSON")?,
            controller,
        ),
        "reset" => CliCommand::execute(Reset, controller),
        "commit" => CliCommand::execute(Commit, controller),
        "run" => CliCommand::execute(
            json::from_str::<Run>(arg).context("Invalid JSON")?,
            controller,
        ),
        _ => bail!("Unknown command {command}"),
    }
}

fn fix_permissions(path: &Path, owner: &str, mode: mode_t) -> Result<()> {
    let (uid, gid) = match owner {
        "user" => (ids::EXTERNAL_USER_UID, ids::EXTERNAL_USER_GID),
        "root" => (ids::EXTERNAL_ROOT_UID, ids::EXTERNAL_ROOT_GID),
        _ => bail!("Invalid owner {owner}"),
    };
    unix_fs::chown(path, Some(uid), Some(gid))
        .with_context(|| format!("Failed to chown {path:?}"))?;
    fs::set_permissions(path, PermissionsExt::from_mode(mode))
        .with_context(|| format!("Failed to chmod {path:?}"))?;
    Ok(())
}
