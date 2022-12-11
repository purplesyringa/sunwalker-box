use crate::linux::{cgroups, running, system};
use anyhow::{Context, Result};
use multiprocessing::Object;
use std::io::ErrorKind;

#[derive(Object)]
pub enum Command {
    RemountReadonly { path: String },
    Run { options: running::Options },
}

#[multiprocessing::entrypoint]
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
            system::change_propagation(&path, system::MS_SLAVE)
                .with_context(|| format!("Failed to change propagation of {path} to slave"))?;

            // If a filesystem was mounted with NOSUID/NODEV/NOEXEC, we won't be able to remount the
            // bind-mount without specifying those same flags. Parsing mountinfo seems slow, and
            // this case isn't going to be triggered often in production anyway, so we just use the
            // shotgun approach for now, bruteforcing the flags in the order of most likeliness.
            let mut result = Ok(());
            for flags in [
                0,
                system::MS_NOSUID,
                system::MS_NODEV,
                system::MS_NOSUID | system::MS_NODEV,
                system::MS_NOEXEC,
                system::MS_NOEXEC | system::MS_NOSUID,
                system::MS_NOEXEC | system::MS_NODEV,
                system::MS_NOEXEC | system::MS_NOSUID | system::MS_NODEV,
            ] {
                result = system::bind_mount_opt(
                    "none",
                    &path,
                    system::MS_REMOUNT | system::MS_RDONLY | flags,
                );
                if let Err(ref e) = result {
                    if let ErrorKind::PermissionDenied = e.kind() {
                        continue;
                    }
                }
                break;
            }

            result.with_context(|| format!("Failed to remount {path} read-only"))?;
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
