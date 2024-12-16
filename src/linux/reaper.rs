use crate::{
    entry,
    linux::{cgroups, ipc, manager, procs, system, system::WaitStatus},
    log,
};
use anyhow::{Context, Result, bail, ensure};
use crossmist::Object;
use libc::c_int;
use rustix::io::{Errno, FdFlags};
use rustix::process::{Pid, RawPid, Signal, WaitOptions};
use rustix::{
    event::{PollFd, PollFlags, Timespec},
    fs::OFlags,
};
use std::os::fd::{AsRawFd, BorrowedFd, OwnedFd, RawFd};

use nix::sys::signal; // FIXME(rustix): runtime API

extern "C" fn pid1_signal_handler(signo: c_int) {
    // std::process::exit is not async-safe
    unsafe {
        libc::_exit(128 + signo);
    }
}

#[derive(Debug, Object)]
pub enum Command {
    Init,
    Reset,
}

#[crossmist::func]
pub fn reaper(
    ppidfd: OwnedFd,
    cli_command: entry::CLIStartCommand,
    cgroup: cgroups::Cgroup,
    reaper_channel: crossmist::Duplex<std::result::Result<Option<String>, String>, Command>,
    manager_channel: crossmist::Duplex<
        std::result::Result<Option<String>, String>,
        manager::Command,
    >,
    log_level: log::LogLevel,
) -> ! {
    std::process::exit(
        match reaper_impl(
            ppidfd,
            cli_command,
            cgroup,
            reaper_channel,
            manager_channel,
            log_level,
        ) {
            Ok(()) => 0,
            Err(e) => {
                eprintln!("{e:?}");
                1
            }
        },
    )
}

fn reaper_impl(
    ppidfd: OwnedFd,
    cli_command: entry::CLIStartCommand,
    cgroup: cgroups::Cgroup,
    mut reaper_channel: crossmist::Duplex<std::result::Result<Option<String>, String>, Command>,
    manager_channel: crossmist::Duplex<
        std::result::Result<Option<String>, String>,
        manager::Command,
    >,
    log_level: log::LogLevel,
) -> Result<()> {
    log::enable_diagnostics("reaper", log_level);

    log!("Reaper started");

    ensure!(
        rustix::process::getpid().is_init(),
        "Reaper must have PID 1"
    );

    // We want to receive some signals, but not handle them immediately
    let mut mask = signal::SigSet::empty();
    mask.add(signal::Signal::SIGUSR1);
    mask.add(signal::Signal::SIGIO);
    mask.add(signal::Signal::SIGCHLD);
    mask.thread_block()
        .context("Failed to configure signal mask")?;

    // PID 1 can't be killed, not even by suicide. Unfortunately, that's exactly what panic! does,
    // so every time panic! is called, it attempts to call abort(2), silently fails and gets stuck
    // in a SIGSEGV loop. That's not what we what, so we set handlers manually.
    for sig in [signal::Signal::SIGSEGV, signal::Signal::SIGABRT] {
        unsafe {
            signal::sigaction(
                sig,
                &signal::SigAction::new(
                    signal::SigHandler::Handler(pid1_signal_handler),
                    signal::SaFlags::empty(),
                    signal::SigSet::empty(),
                ),
            )
        }
        .context("Failed to configure sigaction")?;
    }

    // We want to terminate when parent dies
    rustix::process::set_parent_process_death_signal(Some(Signal::USR1))
        .context("Failed to prctl(PR_SET_PDEATHSIG)")?;

    // In the unlikely case when the parent terminated before or during prctl was called, check if
    // the parent is dead by now. pidfd_send_signal does not work across PID namespaces (not in this
    // case, anyway), so we have to resort to polling.
    if rustix::event::poll(
        &mut [PollFd::new(&ppidfd, PollFlags::IN)],
        Some(&Timespec {
            tv_sec: 0,
            tv_nsec: 0,
        }),
    )
    .context("Failed to poll parent pidfd")?
        != 0
    {
        log!("Parent already dead");
        return Ok(());
    }

    if !cli_command.ignore_non_cloexec {
        // O_CLOEXEC is great and all, but better safe than sorry. We make sure all streams except
        // the standard ones are closed on exec.
        for entry in std::fs::read_dir("/proc/self/fd").context("Failed to read /proc/self/fd")? {
            let entry = entry.context("Failed to read /proc/self/fd")?;
            let raw_fd: RawFd = entry
                .file_name()
                .into_string()
                .ok()
                .context("Invalid filename in /proc/self/fd")?
                .parse()
                .context("Invalid filename in /proc/self/fd")?;
            if raw_fd < 3 {
                continue;
            }
            let fd = unsafe { BorrowedFd::borrow_raw(raw_fd) };
            let flags = rustix::io::fcntl_getfd(fd).context("Failed to fcntl a file descriptor")?;
            if !flags.intersects(FdFlags::CLOEXEC) {
                log!(
                    warn,
                    "Found a non-CLOEXEC file descriptor. This could be due to 'strace', 'perf \
                     trace', or other debugging tools. IF YOU ARE DEBUGGING SUNWALKER, disable \
                     this check with --ignore-non-cloexec. THERE IS SECURITY RISK ATTACHED TO \
                     THIS OPTION -- ONLY USE IT IF YOU ARE SPECIFICALLY DEBUGGING SUNWALKER-BOX."
                );
                bail!("File descriptor {raw_fd} is not CLOEXEC");
            }
        }
    }

    // We don't want to terminate immediately if someone sends Ctrl-C via the controlling terminal,
    // but instead wait for the parent's termination and quit after that. This also prevents command
    // injection via ioctl(TIOCSTI).
    rustix::process::setsid().context("Failed to setsid")?;
    log!("Reaper is now running in a detached controlling terminal");

    // Send a signal whenever a new message appears on a channel
    fn enable_async(channel: &impl AsRawFd, signal: Signal) -> Result<()> {
        let channel = channel.as_raw_fd();

        // Send to pid 1 (i.e. self)
        if unsafe { libc::fcntl(channel, libc::F_SETOWN, 1) } == -1 {
            return Err(std::io::Error::last_os_error()).context("Failed to F_SETOWN");
        }

        const F_SETSIG: c_int = linux_raw_sys::general::F_SETSIG as _;
        if unsafe { libc::fcntl(channel, F_SETSIG, signal.as_raw()) } == -1 {
            return Err(std::io::Error::last_os_error()).context("Failed to F_SETSIG");
        }

        let channel = unsafe { BorrowedFd::borrow_raw(channel) }; // TODO(crossmist): impl AsFd for Duplex
        rustix::fs::fcntl_setfl(
            channel,
            rustix::fs::fcntl_getfl(channel).context("Failed to F_GETFL")? | OFlags::ASYNC,
        )
        .context("Failed to F_SETFL")?;

        Ok(())
    }

    enable_async(&reaper_channel, Signal::IO)
        .context("Failed to enable SIGIO on reaper channel")?;

    // We have to separate reaping and sandbox management, because we need to spawn processes, and
    // reaping all of them continuously is going to be confusing to stdlib.
    let proc_cgroup = cgroup
        .create_proc_cgroup()
        .context("Failed to create box cgroup")?;
    let child = manager::manager
        .spawn(
            proc_cgroup
                .try_clone()
                .expect("Failed to clone box cgroup reference"),
            manager_channel,
            log_level,
        )
        .context("Failed to start child")?;
    // We purposefully don't join manager here, as it may die unexpectedly

    'main: loop {
        match mask.wait().context("Failed to wait for signal")? {
            signal::Signal::SIGUSR1 => {
                // Parent died
                // NOTE: Every log from now on is being sent to stderr after the main process has
                // died. If you are running sunwalker-box fromt terminal, this might mean your
                // shell's prompt is interleaved with log messages. If you are running sunwalker-box
                // under sudo, these logs might be hidden, because sudo redirects stdio, and when
                // sudo dies, output is no longer piped to the user.
                //
                // The latter situation is worse than it sounds. Writing to a pipe that is no longer
                // read by anyone yields EPIPE, and that's bad, because eprintln! panics in this
                // case. For this reason, diagnostics that cannot be logged are silently dropped.
                log!("SIGUSR1: Main process died");
                break 'main;
            }
            signal::Signal::SIGIO => {
                // Incoming command
                let Some(command) = reaper_channel.recv().context("Failed to read command")? else {
                    // SIGIO is also sent when reaper_channel is dropped, which happens just before
                    // the parent dies. However, if we terminate before SIGUSR1, the parent will
                    // believe we crashed. Therefore, just wait for SIGUSR1.
                    log!(
                        "Reaper channel is empty; SIGUSR1 should appear soon or something has \
                         gone wrong"
                    );
                    continue;
                };
                let result = execute_command(command, child.id()).map_err(|e| format!("{e:?}"));
                reaper_channel
                    .send(&result)
                    .context("Failed to report result")?;
            }
            signal::Signal::SIGCHLD => {
                // Child (or several) died
                loop {
                    match system::waitpid(None, WaitOptions::NOHANG) {
                        Ok(WaitStatus::StillAlive) => break,
                        Ok(ws) if Pid::as_raw(ws.pid()) == child.id() => {
                            // Manager died
                            log!("Manager has died");
                            break;
                        }
                        Ok(_) => {}
                        Err(Errno::CHILD) => {
                            // Manager terminated
                            log!(
                                impossible,
                                "No children found but SIGCHLD was sent (or manager death has not \
                                 been handled correctly)"
                            );
                            break 'main;
                        }
                        Err(e) => bail!("Failed to waitpid: {e:?}"),
                    }
                }
            }
            _ => {
                bail!("Unexpected signal");
            }
        }
    }

    // If parent is dead by now, we don't have anyone to report the error to
    log!("Destroying per-sandbox cgroup");
    if let Err(e) = proc_cgroup.destroy() {
        eprintln!("Failed to destroy box cgroup: {e:?}");
    }

    // Don't send the result to the parent
    log!("Terminating");
    Ok(())
}

fn execute_command(command: Command, child_pid: RawPid) -> Result<Option<String>> {
    log!("Running command {command:?}");

    match command {
        Command::Init => {
            ipc::join_process_ipc_namespace(child_pid).context("Failed to join manager's ipcns")?;

            // Mounting /dev/mqueue has to happen a) inside ipcns, b) outside userns. We also don't
            // want to pass fds back and forth, so the reaper is the only reasonable place to do
            // this.
            ipc::mount_mqueue("/newroot/dev/mqueue")
                .context("Failed to mount /newroot/dev/mqueue")?;

            Ok(None)
        }
        Command::Reset => {
            procs::reset_pidns().context("Failed to reset pidns")?;
            ipc::reset().context("Failed to reset IPC namespace")?;
            Ok(None)
        }
    }
}
