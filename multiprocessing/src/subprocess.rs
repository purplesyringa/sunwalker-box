use crate::{duplex, imp, FnOnce, Object, Receiver};
use nix::{
    libc::{c_char, c_int, c_void, pid_t},
    sys::signal,
};
use std::ffi::CString;
use std::io::Result;
use std::os::unix::io::{AsRawFd, RawFd};

pub struct Child<T: Object> {
    proc_pid: nix::unistd::Pid,
    output_rx: Receiver<T>,
}

impl<T: Object> Child<T> {
    pub fn new(proc_pid: nix::unistd::Pid, output_rx: Receiver<T>) -> Child<T> {
        Child {
            proc_pid,
            output_rx,
        }
    }

    pub fn kill(&mut self) -> Result<()> {
        signal::kill(self.proc_pid, signal::Signal::SIGKILL)?;
        Ok(())
    }

    pub fn id(&self) -> pid_t {
        self.proc_pid.as_raw()
    }

    pub fn join(&mut self) -> Result<T> {
        let value = self.output_rx.recv()?;
        let status = nix::sys::wait::waitpid(self.proc_pid, None)?;
        if let nix::sys::wait::WaitStatus::Exited(_, 0) = status {
            value.ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "The subprocess terminated without returning a value",
                )
            })
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!(
                    "The subprocess did not terminate successfully: {:?}",
                    status
                ),
            ))
        }
    }
}

pub(crate) unsafe fn _spawn_child(child_fd: RawFd, flags: c_int) -> Result<nix::unistd::Pid> {
    let child_fd_str = CString::new(child_fd.to_string()).unwrap();

    match nix::libc::syscall(
        nix::libc::SYS_clone,
        nix::libc::SIGCHLD | flags,
        std::ptr::null::<c_void>(),
    ) {
        -1 => Err(std::io::Error::last_os_error()),
        0 => {
            // No heap allocations are allowed from now on
            let res: Result<!> = try {
                signal::sigprocmask(
                    signal::SigmaskHow::SIG_SETMASK,
                    Some(&signal::SigSet::empty()),
                    None,
                )?;
                for i in 1..32 {
                    if i != nix::libc::SIGKILL && i != nix::libc::SIGSTOP {
                        signal::sigaction(
                            signal::Signal::try_from(i).unwrap(),
                            &signal::SigAction::new(
                                signal::SigHandler::SigDfl,
                                signal::SaFlags::empty(),
                                signal::SigSet::empty(),
                            ),
                        )?;
                    }
                }

                imp::disable_cloexec(child_fd)?;

                // nix::unistd::execv uses allocations
                nix::libc::execv(
                    b"/proc/self/exe\0" as *const u8 as *const c_char,
                    &[
                        b"_multiprocessing_\0" as *const u8 as *const c_char,
                        child_fd_str.as_ptr() as *const u8 as *const c_char,
                        std::ptr::null(),
                    ] as *const *const c_char,
                );

                Err(std::io::Error::last_os_error())?;

                unreachable!()
            };

            eprintln!("{}", res.into_err());
            std::process::abort();
        }
        child_pid => Ok(nix::unistd::Pid::from_raw(child_pid as pid_t)),
    }
}

pub unsafe fn spawn<T: Object>(
    entry: Box<dyn FnOnce<(RawFd,), Output = i32>>,
    flags: c_int,
) -> Result<Child<T>> {
    let (mut local, child) = duplex::<Box<dyn FnOnce<(RawFd,), Output = i32>>, T>()?;

    let child_fd = child.as_raw_fd();

    let pid = _spawn_child(child_fd, flags)?;

    local.send(&entry)?;
    Ok(Child::new(pid, local.into_receiver()))
}
