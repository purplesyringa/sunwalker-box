use crate::{
    linux::{cgroups, entry, running, system},
    log,
};
use anyhow::{Context, Result};
use crossmist::Object;
use miniserde::Serialize;
use miniserde_enum::Serialize_enum;
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
    channel: crossmist::Duplex<Result<Option<String>, String>, Command>,
    log_level: log::LogLevel,
) {
    if let Err(e) = manager_impl(proc_cgroup, channel, log_level) {
        eprintln!("{e:?}");
        std::process::exit(1);
    }
}

fn manager_impl(
    proc_cgroup: cgroups::ProcCgroup,
    mut channel: crossmist::Duplex<Result<Option<String>, String>, Command>,
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
            .send(&Ok(Some(entry::Response::from_result(execute_command(
                command,
                &mut runner,
            )))))
            .context("Failed to send reply to channel")?
    }

    Ok(())
}

fn execute_command(
    command: Command,
    runner: &mut running::Runner,
) -> Result<Option<Box<dyn Serialize>>> {
    log!("Running command {command:?}");

    match command {
        Command::RemountReadonly { path } => {
            system::remount_readonly(&path)
                .with_context(|| format!("Failed to remount {path:?} read-only"))?;
            Ok(None)
        }
        Command::Run { options } => {
            let results = runner.run(options)?;

            #[derive(Serialize_enum)]
            enum Limit {
                #[serde(rename = "cpu_time")]
                CpuTime,
                #[serde(rename = "real_time")]
                RealTime,
                #[serde(rename = "idleness_time")]
                IdlenessTime,
                #[serde(rename = "memory")]
                Memory,
            }

            #[derive(Serialize_enum)]
            #[serde(tag = "kind")]
            enum Verdict {
                Exited { exit_code: i32 },
                Signaled { signal_number: i32 },
                LimitExceeded { limit: Limit },
            }

            #[derive(Serialize)]
            struct Metrics {
                cpu_time: f64,
                real_time: f64,
                idleness_time: f64,
                memory: usize,
            }

            #[derive(Serialize)]
            struct Results {
                verdict: Verdict,
                metrics: Metrics,
            }

            let verdict = match results.verdict {
                running::Verdict::ExitCode(exit_code) => Verdict::Exited { exit_code },
                running::Verdict::Signaled(signal_number) => Verdict::Signaled { signal_number },
                running::Verdict::CPUTimeLimitExceeded => Verdict::LimitExceeded {
                    limit: Limit::CpuTime,
                },
                running::Verdict::RealTimeLimitExceeded => Verdict::LimitExceeded {
                    limit: Limit::RealTime,
                },
                running::Verdict::IdlenessTimeLimitExceeded => Verdict::LimitExceeded {
                    limit: Limit::IdlenessTime,
                },
                running::Verdict::MemoryLimitExceeded => Verdict::LimitExceeded {
                    limit: Limit::Memory,
                },
            };

            let metrics = Metrics {
                real_time: results.real_time.as_secs_f64(),
                cpu_time: results.cpu_time.as_secs_f64(),
                idleness_time: results.idleness_time.as_secs_f64(),
                memory: results.memory,
            };

            Ok(Some(Box::new(Results { verdict, metrics })))
        }
    }
}
