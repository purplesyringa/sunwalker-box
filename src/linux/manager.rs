use crate::{
    linux::{cgroups, running, system},
    log,
};
use anyhow::{Context, Result};
use crossmist::Object;
use miniserde::{json, Serialize};
use nix::sys::signal;
use std::path::PathBuf;

#[derive(Debug, Object)]
pub enum Command {
    RemountReadonly { path: PathBuf },
    Run { options: running::Options },
}

#[crossmist::func]
pub fn manager(
    proc_cgroup: cgroups::ProcCgroup,
    channel: crossmist::Duplex<std::result::Result<Option<String>, String>, Command>,
    log_level: log::LogLevel,
) {
    if let Err(e) = manager_impl(proc_cgroup, channel, log_level) {
        eprintln!("{e:?}");
        std::process::exit(1);
    }
}

fn manager_impl(
    proc_cgroup: cgroups::ProcCgroup,
    mut channel: crossmist::Duplex<std::result::Result<Option<String>, String>, Command>,
    log_level: log::LogLevel,
) -> Result<()> {
    log::enable_diagnostics("manager", log_level);

    log!("Manager started");

    // Cancel signal blocking by reaper
    signal::SigSet::empty()
        .thread_set_mask()
        .context("Failed to configure signal mask")?;

    let mut runner = running::Runner::new(proc_cgroup).context("Failed to create runner")?;

    log!("Ready to receive commands");
    channel
        .send(&Ok(None))
        .context("Failed to notify parent about readiness")?;

    while let Some(command) = channel
        .recv()
        .context("Failed to receive message from channel")?
    {
        channel
            .send(&match execute_command(command, &mut runner) {
                Ok(value) => Ok(value),
                Err(e) => Err(format!("{e:?}")),
            })
            .context("Failed to send reply to channel")?
    }

    Ok(())
}

fn execute_command(command: Command, runner: &mut running::Runner) -> Result<Option<String>> {
    log!("Running command {command:?}");

    match command {
        Command::RemountReadonly { path } => {
            system::remount_readonly(&path)
                .with_context(|| format!("Failed to remount {path:?} read-only"))?;
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

            #[derive(Serialize)]
            struct Results {
                limit_verdict: &'static str,
                exit_code: i32,
                real_time: f64,
                cpu_time: f64,
                idleness_time: f64,
                memory: usize,
            }

            Ok(Some(json::to_string(&Results {
                limit_verdict,
                exit_code,
                real_time: results.real_time.as_secs_f64(),
                cpu_time: results.cpu_time.as_secs_f64(),
                idleness_time: results.idleness_time.as_secs_f64(),
                memory: results.memory,
            })))
        }
    }
}
