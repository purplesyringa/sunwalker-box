use crate::linux::{cgroups, rootfs, system, timens, userns};
use anyhow::{bail, Context, Result};
use multiprocessing::Object;
use nix::{
    libc,
    libc::SYS_pidfd_open,
    sys::{signal, wait},
};
use std::ffi::CString;
use std::io::ErrorKind;
use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::time::{Duration, Instant};

#[derive(Object)]
pub enum Command {
    RemountReadonly {
        path: String,
    },
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

#[multiprocessing::entrypoint]
pub fn manager(
    proc_cgroup: cgroups::ProcCgroup,
    mut channel: multiprocessing::Duplex<std::result::Result<Option<String>, String>, Command>,
) {
    // Mount procfs and enter the sandboxed root
    rootfs::configure_rootfs().expect("Failed to configure rootfs");
    let mut timens_controller = timens::TimeNsController::new().expect("Failed to adjust time");
    userns::enter_user_namespace().expect("Failed to unshare user namespace");
    rootfs::enter_rootfs().expect("Failed to enter rootfs");

    channel
        .send(&Ok(None))
        .expect("Failed to notify parent about readiness");

    while let Some(command) = channel
        .recv()
        .expect("Failed to receive message from channel")
    {
        channel
            .send(
                &match execute_command(command, &proc_cgroup, &mut timens_controller) {
                    Ok(value) => Ok(value),
                    Err(e) => Err(format!("{e:?}")),
                },
            )
            .expect("Failed to send reply to channel")
    }
}

fn execute_command(
    command: Command,
    proc_cgroup: &cgroups::ProcCgroup,
    timens_controller: &mut timens::TimeNsController,
) -> Result<Option<String>> {
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
            timens_controller
                .reset_system_time_for_children()
                .context("Failed to virtualize boot time")?;

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
            let box_cgroup = proc_cgroup
                .create_box_cgroup()
                .context("Failed to create user cgroup")?;
            if let Some(memory_limit) = memory_limit {
                box_cgroup
                    .set_memory_limit(memory_limit)
                    .context("Failed to apply memory limit")?;
            }
            if let Some(processes_limit) = processes_limit {
                box_cgroup
                    .set_processes_limit(processes_limit)
                    .context("Failed to apply processes limit")?;
            }
            box_cgroup
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

            let has_peak = box_cgroup.get_memory_peak()?.is_some();

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
                let cpu_stats = box_cgroup.get_cpu_stats()?;
                metrics.cpu_time = cpu_stats.total;
                metrics.real_time = start_time.elapsed();
                metrics.idleness_time = metrics.real_time.saturating_sub(metrics.cpu_time);
                if !has_peak {
                    metrics.memory = metrics.memory.max(box_cgroup.get_memory_total()?);
                }

                if exitted {
                    break;
                }

                // Check if any limits were exceeded
                if real_time_limit.is_some_and(|limit| metrics.real_time > limit)
                    || cpu_time_limit.is_some_and(|limit| metrics.cpu_time > limit)
                    || idleness_time_limit.is_some_and(|limit| metrics.idleness_time > limit)
                    || memory_limit.is_some_and(|limit| metrics.memory > limit)
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

                // Switching context takes time, some other operations take time too, etc., so less
                // CPU time is usually used than permitted. We also don't really want to interrupt
                // the process. We need to set a low limit on the timeout as well.
                //
                // In practice, adding 50ms seems like a good solution. This is not too big a number
                // to slow the judgment, not too small to steal resources from the solution in what
                // is effectively a spin lock, and allows SIGPROF to fire just at the right moment
                // under normal circumstances.
                if let Some(cpu_time_limit) = cpu_time_limit {
                    timeout =
                        timeout.min(cpu_time_limit - metrics.cpu_time + Duration::from_millis(50));
                }

                // Similarly, a process cannot exceed its idleness time limit during
                // idleness_time_left seconds. It is not obvious how idleness time is to interact
                // with multicore programs, so we should forbid the limit in this case (TODO).
                //
                // We add 50ms here too, because when little idleness time is left, the process
                // might just spend the rest of time crunching CPU cycles without spending idleness
                // time.
                if let Some(idleness_time_limit) = idleness_time_limit {
                    timeout = timeout.min(
                        idleness_time_limit - metrics.idleness_time + Duration::from_millis(50),
                    );
                }

                // Old kernels don't reveal memory.peak, so the only way to get memory usage stats
                // is to use polling
                if !has_peak {
                    timeout = Duration::from_millis(50);
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
                    box_cgroup
                        .get_memory_peak()?
                        .context("memory.peak is unexpectedly unavailable")?,
                );
            }

            let mut limit_verdict;
            if cpu_time_limit.is_some_and(|limit| metrics.cpu_time > limit) {
                limit_verdict = "CPUTimeLimitExceeded";
            } else if real_time_limit.is_some_and(|limit| metrics.real_time > limit) {
                limit_verdict = "RealTimeLimitExceeded";
            } else if idleness_time_limit.is_some_and(|limit| metrics.idleness_time > limit) {
                limit_verdict = "IdlenessTimeLimitExceeded";
            } else if box_cgroup.was_oom_killed()?
                || memory_limit.is_some_and(|limit| metrics.memory > limit)
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
                            exit_code = -(signal as i32);
                        }
                        _ => {
                            bail!("waitpid returned unexpected status: {wait_status:?}");
                        }
                    }
                }
            } else {
                assert!(limit_verdict != "OK");
            }

            box_cgroup
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

        std::env::set_current_dir("/space").context("Failed to chdir to /space")?;

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
