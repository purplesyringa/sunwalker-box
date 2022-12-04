use crate::{
    entry,
    linux::{cgroups, manager, procs},
};
use anyhow::{Context, Result};
use multiprocessing::Object;
use nix::{
    libc,
    libc::{c_int, PR_SET_PDEATHSIG, SIGUSR1},
    sys::{signal, wait},
};
use std::os::unix::io::{AsRawFd, OwnedFd, RawFd};

extern "C" fn pid1_signal_handler(signo: c_int) {
    // std::process::exit is not async-safe
    unsafe {
        libc::_exit(128 + signo);
    }
}

#[derive(Object)]
pub enum Command {
    Reset,
}

#[multiprocessing::entrypoint]
pub fn reaper(
    ppidfd: OwnedFd,
    cli_command: entry::CLIStartCommand,
    cgroup: cgroups::Cgroup,
    mut reaper_channel: multiprocessing::Duplex<
        std::result::Result<Option<String>, String>,
        Command,
    >,
    manager_channel: multiprocessing::Duplex<
        std::result::Result<Option<String>, String>,
        manager::Command,
    >,
) -> ! {
    if nix::unistd::getpid().as_raw() != 1 {
        panic!("Reaper must have PID 1");
    }

    // We want to receive SIGUSR1 and SIGCHLD, but not handle them immediately
    let mut mask = signal::SigSet::empty();
    mask.add(signal::Signal::SIGUSR1);
    mask.add(signal::Signal::SIGIO);
    mask.add(signal::Signal::SIGCHLD);
    if let Err(e) = mask.thread_block() {
        eprintln!("Failed to configure signal mask: {e}");
        std::process::exit(1);
    }

    // PID 1 can't be killed, not even by suicide. Unfortunately, that's exactly what panic! does,
    // so every time panic! is called, it attempts to call abort(2), silently fails and gets stuck
    // in a SIGSEGV loop. That's not what we what, so we set handlers manually.
    for sig in [signal::Signal::SIGSEGV, signal::Signal::SIGABRT] {
        if let Err(e) = unsafe {
            signal::sigaction(
                sig,
                &signal::SigAction::new(
                    signal::SigHandler::Handler(pid1_signal_handler),
                    signal::SaFlags::empty(),
                    signal::SigSet::empty(),
                ),
            )
        } {
            eprintln!("Failed to configure sigaction: {e}");
            std::process::exit(1);
        }
    }

    // We want to terminate when parent dies
    if unsafe { libc::prctl(PR_SET_PDEATHSIG, SIGUSR1) } == -1 {
        panic!(
            "Failed to prctl(PR_SET_PDEATHSIG): {}",
            std::io::Error::last_os_error()
        );
    }
    // In the unlikely case when the parent terminated before or during prctl was called, check if
    // the parent is dead by now. pidfd_send_signal does not work across PID namespaces (not in this
    // case, anyway), so we have to resort to polling.
    if nix::poll::poll(
        &mut [nix::poll::PollFd::new(
            ppidfd.as_raw_fd(),
            nix::poll::PollFlags::POLLIN,
        )],
        0,
    )
    .expect("Failed to poll parent pidfd")
        != 0
    {
        std::process::exit(0);
    }

    if !cli_command.ignore_non_cloexec {
        // O_CLOEXEC is great and all, but better safe than sorry. We make sure all streams except
        // the standard ones are closed on exec.
        for entry in std::fs::read_dir("/proc/self/fd").expect("Failed to read /proc/self/fd") {
            let entry = entry.expect("Failed to read /proc/self/fd");
            let fd: RawFd = entry
                .file_name()
                .into_string()
                .expect("Invalid filename in /proc/self/fd")
                .parse()
                .expect("Invalid filename in /proc/self/fd");
            if fd < 3 {
                continue;
            }
            let flags = nix::fcntl::fcntl(fd, nix::fcntl::FcntlArg::F_GETFD)
                .expect("Failed to fcntl a file descriptor");
            if !nix::fcntl::FdFlag::from_bits_truncate(flags)
                .intersects(nix::fcntl::FdFlag::FD_CLOEXEC)
            {
                panic!("File descriptor {fd} is not CLOEXEC");
            }
        }
    }

    // We don't want to terminate immediately if someone sends Ctrl-C via the controlling terminal,
    // but instead wait for the parent's termination and quit after that.
    nix::unistd::setsid().expect("Failed to setsid");

    // We have to separate reaping and sandbox management, because we need to spawn processes, and
    // reaping all of them continuously is going to be confusing to stdlib.
    let proc_cgroup = cgroup
        .create_proc_cgroup()
        .expect("Failed to create box cgroup");
    let child = manager::manager
        .spawn(
            proc_cgroup
                .try_clone()
                .expect("Failed to clone box cgroup reference"),
            manager_channel,
        )
        .expect("Failed to start child");
    // We purposefully don't join manager here, as it may die unexpectedly

    'main: loop {
        let mut sigset = signal::SigSet::empty();
        sigset.add(signal::Signal::SIGUSR1);
        sigset.add(signal::Signal::SIGIO);
        sigset.add(signal::Signal::SIGCHLD);
        match sigset.wait().expect("Failed to wait for signal") {
            signal::Signal::SIGUSR1 => {
                // Parent died
                break 'main;
            }
            signal::Signal::SIGIO => {
                // Incoming command
                let result = execute_command(
                    reaper_channel
                        .recv()
                        .expect("Failed to read command")
                        .expect("No command received"),
                );
                let result = result.map_err(|e| format!("{e:?}"));
                reaper_channel
                    .send(&result)
                    .expect("Failed to report result");
            }
            signal::Signal::SIGCHLD => {
                // Child (or several) died
                loop {
                    match wait::waitpid(None, Some(wait::WaitPidFlag::WNOHANG)) {
                        Ok(res) => {
                            if res.pid() == Some(nix::unistd::Pid::from_raw(child.id())) {
                                // Manager died
                                break;
                            }
                            if res == wait::WaitStatus::StillAlive {
                                break;
                            }
                        }
                        Err(e) => {
                            if e == nix::errno::Errno::ECHILD {
                                // Manager terminated
                                break 'main;
                            } else {
                                panic!("Failed to waitpid: {e:?}");
                            }
                        }
                    }
                }
            }
            _ => {
                panic!("Unexpected signal");
            }
        }
    }

    // If parent is dead by now, we don't have anyone to report the error to
    if let Err(e) = proc_cgroup.destroy() {
        eprintln!("Failed to destroy box cgroup: {e:?}");
    }

    // Don't send the result to the parent
    std::process::exit(0)
}

fn execute_command(command: Command) -> Result<Option<String>> {
    match command {
        Command::Reset => {
            procs::reset_pidns().context("Failed to reset pidns")?;
            Ok(None)
        }
    }
}
