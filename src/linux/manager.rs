use crate::linux::{cgroups, running, system};
use anyhow::{Context, Result};
use multiprocessing::Object;

#[derive(Object)]
pub enum Command {
    RemountReadonly { path: String },
    Run { options: running::Options },
}

#[multiprocessing::func]
pub fn manager(
    proc_cgroup: cgroups::ProcCgroup,
    mut channel: multiprocessing::Duplex<std::result::Result<Option<String>, String>, Command>,
) {
    let mut runner = running::Runner::new(proc_cgroup).expect("Failed to create runner");

    channel
        .send(&Ok(None))
        .expect("Failed to notify parent about readiness");

    while let Some(command) = channel
        .recv()
        .expect("Failed to receive message from channel")
    {
        channel
            .send(&match execute_command(command, &mut runner) {
                Ok(value) => Ok(value),
                Err(e) => Err(format!("{e:?}")),
            })
            .expect("Failed to send reply to channel")
    }
}

fn execute_command(command: Command, runner: &mut running::Runner) -> Result<Option<String>> {
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
