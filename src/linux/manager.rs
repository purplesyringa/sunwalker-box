use crate::{
    linux::{cgroups, reaper, running, system},
    log,
};
use anyhow::{Context, Result};
use crossmist::Object;

#[derive(Debug, Object)]
pub enum Command {
    RemountReadonly { path: String },
    Run { options: running::Options },
}

#[crossmist::func]
pub fn manager(
    proc_cgroup: cgroups::ProcCgroup,
    mut entry_channel: crossmist::Duplex<Result<Option<String>, String>, Command>,
    reaper_channel: crossmist::Duplex<reaper::Request, Result<reaper::Response, String>>,
    log_level: log::LogLevel,
) {
    log::enable_diagnostics("manager", log_level);

    log!("Manager started");

    let runner =
        running::Runner::new(proc_cgroup, reaper_channel).expect("Failed to create runner");

    log!("Ready to receive commands");
    entry_channel
        .send(&Ok(None))
        .expect("Failed to notify parent about readiness");

    while let Some(command) = entry_channel
        .recv()
        .expect("Failed to receive message from entry channel")
    {
        entry_channel
            .send(&match execute_command(command, &runner) {
                Ok(value) => Ok(value),
                Err(e) => Err(format!("{e:?}")),
            })
            .expect("Failed to send reply to entry channel")
    }
}

fn execute_command(command: Command, runner: &running::Runner) -> Result<Option<String>> {
    log!("Running command {command:?}");

    match command {
        Command::RemountReadonly { path } => {
            system::remount_readonly(&path)
                .with_context(|| format!("Failed to remount {path} read-only"))?;
            Ok(None)
        }
        Command::Run { options } => {
            let results = runner.run(options)?;

            let limit_verdict;
            let mut exit_code = -1;

            match results.verdict {
                running::Verdict::ExitCode(exit_code_) => {
                    limit_verdict = "OK";
                    exit_code = exit_code_;
                }
                running::Verdict::Signaled(signal_number) => {
                    limit_verdict = "Signaled";
                    exit_code = -signal_number;
                }
                running::Verdict::CPUTimeLimitExceeded => {
                    limit_verdict = "CPUTimeLimitExceeded";
                }
                running::Verdict::RealTimeLimitExceeded => {
                    limit_verdict = "RealTimeLimitExceeded";
                }
                running::Verdict::IdlenessTimeLimitExceeded => {
                    limit_verdict = "IdlenessTimeLimitExceeded";
                }
                running::Verdict::MemoryLimitExceeded => {
                    limit_verdict = "MemoryLimitExceeded";
                }
            }

            Ok(Some(json::stringify(json::object! {
                limit_verdict: limit_verdict,
                exit_code: exit_code,
                real_time: results.real_time.as_secs_f64(),
                cpu_time: results.cpu_time.as_secs_f64(),
                idleness_time: results.idleness_time.as_secs_f64(),
                memory: results.memory,
            })))
        }
    }
}
