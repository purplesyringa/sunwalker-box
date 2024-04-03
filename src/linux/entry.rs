use crate::{
    entry,
    linux::{cgroups, controller, kmodule, manager, rootfs, running, sandbox},
    log,
    log::LogLevel,
};
use anyhow::{anyhow, bail, Context, Result};
use miniserde::{json, Deserialize, Serialize};
use miniserde_enum::{Deserialize_enum, Serialize_enum};
use std::collections::HashMap;
use std::io;
use std::io::{BufRead, BufReader};
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
        let request = line.context("Failed to read from stdin")?;
        let response = match json::from_str::<Command>(&request) {
            Ok(command) => command.execute(&mut controller),
            Err(error) => Response::error(&anyhow::Error::new(error)),
        };
        println!("{response}");
    }

    log!("Terminating");
    Ok(())
}

trait CliCommand {
    fn execute(self, controller: &mut controller::Controller) -> Result<impl Serialize + 'static>;

    fn execute_to_str(self, controller: &mut controller::Controller) -> String
    where
        Self: Sized,
    {
        Response::from_result(self.execute(controller))
    }
}

struct Extpath;

impl CliCommand for Extpath {
    fn execute(self, _controller: &mut controller::Controller) -> Result<impl Serialize + 'static> {
        let path = rootfs::resolve_abs_box_root("/")?;
        let pid = process::id();
        let system_path = format!(
            "/proc/{pid}/root{}",
            path.to_str().context("Path is not UTF-8")?
        );
        Ok(system_path)
    }
}

#[derive(Deserialize)]
struct Bind {
    source: String,
    mountpoint: String,
    readonly: bool,
}

impl CliCommand for Bind {
    fn execute(self, controller: &mut controller::Controller) -> Result<impl Serialize + 'static> {
        controller.bind(&self.source, &self.mountpoint, self.readonly)?;
        Ok(())
    }
}

struct Reset;

impl CliCommand for Reset {
    fn execute(self, controller: &mut controller::Controller) -> Result<impl Serialize + 'static> {
        controller.reset()?;
        Ok(())
    }
}

struct Commit;

impl CliCommand for Commit {
    fn execute(self, controller: &mut controller::Controller) -> Result<impl Serialize + 'static> {
        controller.commit()?;
        Ok(())
    }
}

#[derive(Default, Deserialize)]
struct Stdio {
    stdin: Option<String>,
    stdout: Option<String>,
    stderr: Option<String>,
}

#[derive(Default, Deserialize)]
struct Limits {
    real_time: Option<f64>,
    cpu_time: Option<f64>,
    idleness_time: Option<f64>,
    memory: Option<usize>,
    processes: Option<usize>,
}

#[derive(Deserialize)]
struct Run {
    argv: Vec<String>,
    env: Option<HashMap<String, String>>,
    stdio: Option<Stdio>,
    limits: Option<Limits>,
}

impl CliCommand for Run {
    fn execute_to_str(self, controller: &mut controller::Controller) -> String {
        if self.argv.is_empty() {
            return Response::error(&anyhow!("argv should not be empty"));
        }

        let dev_null = || "/dev/null".to_owned();
        let stdio = self.stdio.unwrap_or_default();
        let limits = self.limits.unwrap_or_default();

        let result = controller.run_manager_command(manager::Command::Run {
            options: running::Options {
                argv: self.argv,
                stdin: stdio.stdin.unwrap_or_else(dev_null),
                stdout: stdio.stdout.unwrap_or_else(dev_null),
                stderr: stdio.stderr.unwrap_or_else(dev_null),
                real_time_limit: limits.real_time.map(Duration::from_secs_f64),
                cpu_time_limit: limits.cpu_time.map(Duration::from_secs_f64),
                idleness_time_limit: limits.idleness_time.map(Duration::from_secs_f64),
                memory_limit: limits.memory,
                processes_limit: limits.processes,
                env: self.env,
            },
        });

        match result {
            Ok(Some(thing)) => thing,
            Ok(None) => Response::success(&()),
            Err(error) => Response::error(&error),
        }
    }

    #[allow(refining_impl_trait)]
    fn execute(self, _: &mut controller::Controller) -> Result<()> {
        bail!("Not meant to be called like this")
    }
}

#[derive(Serialize_enum)]
#[serde(tag = "status")]
pub enum Response {
    Success { data: Box<dyn Serialize> },
    Error { error: String },
}

impl Response {
    pub fn success(value: &'static dyn Serialize) -> String {
        json::to_string(&Self::Success {
            data: Box::new(value),
        })
    }
    pub fn error(value: &anyhow::Error) -> String {
        json::to_string(&Self::Error {
            error: format!("{value:?}"),
        })
    }
    pub fn from_result(value: Result<impl Serialize + 'static>) -> String {
        json::to_string(&match value {
            Ok(data) => Self::Success {
                data: Box::new(data),
            },
            Err(error) => Self::Error {
                error: format!("{error:?}"),
            },
        })
    }
}

#[derive(Deserialize_enum)]
#[serde(tag = "command", content = "payload")]
enum Command {
    #[serde(rename = "extpath")]
    Extpath,
    #[serde(rename = "bind")]
    Bind(Bind),
    #[serde(rename = "reset")]
    Reset,
    #[serde(rename = "commit")]
    Commit,
    #[serde(rename = "run")]
    Run(Run),
}

impl Command {
    fn execute(self, controller: &mut controller::Controller) -> String {
        match self {
            Command::Extpath => Extpath.execute_to_str(controller),
            Command::Bind(bind) => bind.execute_to_str(controller),
            Command::Reset => Reset.execute_to_str(controller),
            Command::Commit => Commit.execute_to_str(controller),
            Command::Run(run) => run.execute_to_str(controller),
        }
    }
}
