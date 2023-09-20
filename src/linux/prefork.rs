use crate::{
    linux::{ids, reaper, sandbox, system, timens, tracing},
    log,
};
use anyhow::{anyhow, bail, Context, Result};
use crossmist::Object;
use nix::{
    fcntl, libc,
    libc::{dev_t, off_t},
    sys::{ptrace, signal, stat, wait},
    unistd,
    unistd::Pid,
};
use std::cell::{Cell, RefCell};
use std::ffi::CStr;
use std::fs::File;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::time::Instant;

pub struct PreForkManager {
    stdio_subst: File,
    stdio_subst_devino: (u64, u64),
    white_list_rdev: Vec<dev_t>,
    request_channel: RefCell<crossmist::Duplex<reaper::Request, Result<reaper::Response, String>>>,
}

pub struct PreForkRun<'a> {
    manager: &'a PreForkManager,
    state: Cell<State>,
}

#[derive(Object)]
pub struct SuspendOptions {
    ignore_fd: Option<i32>,
    restart_syscall: bool,
    inside_syscall: bool,
}

#[derive(Clone, Copy, Debug)]
enum State {
    NotStarted,
    Alive,
    WaitingOnOpen,
}

pub struct Suspender {
    options: SuspendOptions,
    orig: tracing::TracedProcess,
    slave: Option<tracing::TracedProcess>,
    syscall_page_location: usize,
    registers: tracing::Registers,
    started: Instant,
}

#[repr(C)]
#[derive(Debug)]
struct prctl_mm_map {
    start_code: usize,
    end_code: usize,
    start_data: usize,
    end_data: usize,
    start_brk: usize,
    brk: usize,
    start_stack: usize,
    arg_start: usize,
    arg_end: usize,
    env_start: usize,
    env_end: usize,
    auxv: usize,
    auxv_size: u32,
    exe_fd: u32,
}

const SUSPENDER_PIDFD_FIXED_FD: RawFd = 1;

impl SuspendOptions {
    fn new_seccomp() -> Self {
        Self {
            ignore_fd: None,
            restart_syscall: false,
            inside_syscall: true,
        }
    }

    fn new_after_open(fd: RawFd) -> Self {
        Self {
            ignore_fd: Some(fd),
            restart_syscall: true,
            inside_syscall: false,
        }
    }
}

impl PreForkManager {
    pub fn new(
        stdio_subst: File,
        request_channel: crossmist::Duplex<reaper::Request, Result<reaper::Response, String>>,
    ) -> Result<Self> {
        let stdio_subst_stat =
            stat::fstat(stdio_subst.as_raw_fd()).context("Failed to stat /stdiosubst")?;
        let stdio_subst_devino = (stdio_subst_stat.st_dev, stdio_subst_stat.st_ino);

        let white_list_rdev = vec![
            Self::get_rdev("/dev/urandom")?,
            Self::get_rdev("/dev/null")?,
            Self::get_rdev("/dev/zero")?,
        ];

        Ok(Self {
            stdio_subst,
            stdio_subst_devino,
            white_list_rdev,
            request_channel: RefCell::new(request_channel),
        })
    }

    fn get_rdev(path: &str) -> Result<dev_t> {
        Ok(stat::stat(path)
            .with_context(|| format!("Failed to stat {path}"))?
            .st_rdev)
    }

    pub fn run(&self) -> PreForkRun {
        PreForkRun {
            manager: self,
            state: Cell::new(State::NotStarted),
        }
    }

    pub fn get_stdio_subst(&self) -> Result<File> {
        self.stdio_subst
            .try_clone()
            .context("Failed to clone stdio_subst")
    }
}

impl PreForkRun<'_> {
    fn suspend(&self, orig: &mut tracing::TracedProcess, options: SuspendOptions) -> Result<()> {
        let started = Instant::now();
        log!("Suspend started on {started:?}");

        use tracing::SyscallArgs;
        let syscall_info = orig
            .get_syscall_info()
            .context("Failed to get syscall info")?;
        let syscall_info = unsafe { syscall_info.u.seccomp };
        log!(
            "Suspending on {}",
            (
                syscall_info.nr,
                syscall_info.args[0],
                syscall_info.args[1],
                syscall_info.args[2],
                syscall_info.args[3],
                syscall_info.args[4],
                syscall_info.args[5],
            )
                .debug()
        );

        // We want to detach from the original process, allowing the suspender to attach to it.
        // Unfortunately, we can't reliably stop the process before detaching, so it might execute a
        // few instructions, which we want to prevent. Therefore, we save the register bank, and
        // make the process execute raise(SIGSTOP). TODO: This might fail if another signal is
        // delivered during execution of this syscall. Check if that's actually the case.
        orig.deinit()?;
        if options.restart_syscall {
            // Jump back to the syscall instruction
            let ip = orig.get_instruction_pointer()? - orig.get_syscall_insn_length();
            orig.set_instruction_pointer(ip)?;
        }
        // Save current register state because we might corrupt it by calling kill()
        let registers = orig.get_registers()?;
        orig.exec_syscall(
            (libc::SYS_kill, orig.get_pid().as_raw(), libc::SIGSTOP),
            options.inside_syscall,
        )
        .context("Failed to raise(SIGSTOP) in the original process")?;
        orig.detach()?;

        if let reaper::Response::SuspendProcess = self
            .manager
            .request_channel
            .borrow_mut()
            .request(&reaper::Request::SuspendProcess {
                pid: orig.get_pid().as_raw(),
                options,
                registers,
                started,
            })
            .context("Failed to perform request in reaper")?
            .map_err(|e| anyhow!("{e}"))
            .context("Error during suspend request")?
        {
            Ok(())
        } else {
            bail!("Invalid return type to manager request");
        }
    }

    pub fn on_seccomp(&self, orig: &mut tracing::TracedProcess) -> Result<()> {
        let syscall_info = orig
            .get_syscall_info()
            .context("Failed to get syscall info")?;
        let syscall_info = unsafe { syscall_info.u.seccomp };

        // Allow all operations we can checkpoint-restore that don't touch the filesystem in an
        // impure way, e.g. open an fd to a file that can later be written to or to the standard
        // stream that might later be redirected somewhere else
        match syscall_info.nr as i64 {
            libc::SYS_close
            | libc::SYS_close_range
            | libc::SYS_read
            | libc::SYS_pread64
            | libc::SYS_readv
            | libc::SYS_dup
            | libc::SYS_preadv
            | libc::SYS_preadv2 => {
                let fd = syscall_info.args[0] as i32;
                if (0..3).contains(&fd) {
                    return self.suspend(orig, SuspendOptions::new_seccomp());
                }
            }
            libc::SYS_lseek => {
                let fd = syscall_info.args[0] as i32;
                let offset = syscall_info.args[1] as off_t;
                let whence = syscall_info.args[2] as i32;
                if (0..3).contains(&fd) {
                    // Disallow seeking to anywhere but the beginning
                    if offset != 0 || (whence != libc::SEEK_SET && whence != libc::SEEK_CUR) {
                        return self.suspend(orig, SuspendOptions::new_seccomp());
                    }
                }
            }
            libc::SYS_mmap => {
                return self.suspend(orig, SuspendOptions::new_seccomp());
            }
            libc::SYS_dup2 | libc::SYS_dup3 => {
                let oldfd = syscall_info.args[0] as i32;
                let newfd = syscall_info.args[1] as i32;
                if (0..3).contains(&oldfd) || (0..3).contains(&newfd) {
                    return self.suspend(orig, SuspendOptions::new_seccomp());
                }
            }
            libc::SYS_open | libc::SYS_openat => {
                // TOCTOU is not a problem as the user process is single-threaded
                self.state.set(State::WaitingOnOpen);
                return orig.resume_syscall();
            }
            libc::SYS_fcntl => {
                let fd = syscall_info.args[0] as i32;
                let cmd = syscall_info.args[1] as i32;
                if (0..3).contains(&fd)
                    && cmd != libc::F_GETFD
                    && cmd != libc::F_SETFD
                    && cmd != libc::F_GETFL
                {
                    return self.suspend(orig, SuspendOptions::new_seccomp());
                }
            }
            libc::SYS_ioctl => {
                let fd = syscall_info.args[0] as i32;
                let request = syscall_info.args[1];
                if (0..3).contains(&fd) {
                    // These will return ENOTTY/ENOTSOCK anyway
                    if request != libc::TCGETS as u64 && request != libc::TIOCGPGRP as u64 {
                        return self.suspend(orig, SuspendOptions::new_seccomp());
                    }
                }
            }
            libc::SYS_prctl => {
                let option = syscall_info.args[0] as i32;
                let arg2 = syscall_info.args[1] as i32;
                match (option, arg2) {
                    (libc::PR_CAP_AMBIENT, libc::PR_CAP_AMBIENT_IS_SET) => {}
                    (libc::PR_CAPBSET_READ, _) => {}
                    (libc::PR_GET_CHILD_SUBREAPER, _) => {}
                    (libc::PR_GET_DUMPABLE, _) => {}
                    (libc::PR_GET_KEEPCAPS, _) => {}
                    (libc::PR_MCE_KILL_GET, _) => {}
                    (libc::PR_GET_NAME, _) => {}
                    (libc::PR_GET_NO_NEW_PRIVS, _) => {}
                    (libc::PR_GET_PDEATHSIG, _) => {}
                    (libc::PR_GET_SECCOMP, _) => {}
                    (libc::PR_GET_SECUREBITS, _) => {}
                    (libc::PR_SET_THP_DISABLE, _) => {}
                    // (libc::PR_GET_THP_DISABLE, _) => {} -- handled in seccomp
                    // (libc::PR_GET_TID_ADDRESS, _) => {} -- handled in seccomp
                    (libc::PR_GET_TIMERSLACK, _) => {}
                    (libc::PR_GET_TIMING, _) => {}
                    (libc::PR_GET_TSC, _) => {}
                    _ => {
                        return self.suspend(orig, SuspendOptions::new_seccomp());
                    }
                }
            }
            libc::SYS_getppid => {
                // As if across PID namespace
                orig.set_syscall_result(0)?;
                orig.set_syscall_no(-1)?; // skip syscall
            }
            // TODO: pipe, sysinfo, modify_ldt, epoll*
            // TODO: move simple cases to seccomp filter for efficiency
            _ => {
                return self.suspend(orig, SuspendOptions::new_seccomp());
            }
        }

        orig.resume()
    }

    pub fn handle_syscall(&mut self, orig: &mut tracing::TracedProcess) -> Result<()> {
        match self
            .should_suspend_after_syscall(orig)
            .context("Failed to check if should suspend after syscsall")?
        {
            Some(options) => self
                .suspend(orig, options)
                .context("Failed to suspend after syscall"),
            None => orig.resume(),
        }
    }

    fn should_suspend_after_syscall(
        &mut self,
        orig: &mut tracing::TracedProcess,
    ) -> Result<Option<SuspendOptions>> {
        match self.state.get() {
            State::WaitingOnOpen => {
                self.state.set(State::Alive);

                let fd = orig.get_syscall_result()? as i32;
                if fd < 0 {
                    return Ok(None);
                }

                let path = format!("/proc/{}/fd/{fd}", orig.get_pid());

                let fd_stat =
                    stat::stat(path.as_str()).with_context(|| format!("Failed to open {path}"))?;

                if self.manager.white_list_rdev.contains(&fd_stat.st_rdev) {
                    // Some files may be writable but are stateless, so we don't have to bother
                    // saving their contents
                    return Ok(None);
                }

                if (fd_stat.st_dev, fd_stat.st_ino) == self.manager.stdio_subst_devino {
                    // Doing stuff with stdio
                    log!("Suspending on stdio");
                    return Ok(Some(SuspendOptions::new_after_open(fd)));
                }

                // Is it possible that the user process later writes into the same file?
                // Assumes that UID and GID can't be changed, and ACL is not present
                let stat_mode = stat::Mode::from_bits_truncate(fd_stat.st_mode);
                let uid = fd_stat.st_uid;
                let gid = fd_stat.st_uid;
                let writable = if uid == ids::INTERNAL_USER_UID {
                    stat_mode.contains(stat::Mode::S_IWUSR)
                } else if gid == ids::INTERNAL_USER_GID {
                    stat_mode.contains(stat::Mode::S_IWGRP)
                } else {
                    stat_mode.contains(stat::Mode::S_IWOTH)
                };

                if writable {
                    log!(
                        "Suspending on writable file {} {:?}",
                        fd_stat.st_rdev,
                        self.manager.white_list_rdev
                    );
                    return Ok(Some(SuspendOptions::new_after_open(fd)));
                }
            }

            _ => bail!("PtraceSyscall on unexpected state {:?}", self.state.get()),
        }

        Ok(None)
    }
}

impl Suspender {
    pub fn new(
        pid: Pid,
        options: SuspendOptions,
        registers: tracing::Registers,
        started: Instant,
    ) -> Result<Self> {
        Ok(Self {
            options,
            orig: tracing::TracedProcess::new_external(pid, true)?,
            slave: None,
            syscall_page_location: 0,
            registers,
            started,
        })
    }

    pub fn suspend(&mut self) -> Result<()> {
        // We would like to detach the restricted seccomp filter and attach the normal one.
        // Unfortunately, seccomp filters cannot be removed, so we have to cheat and create a new
        // process, effectively running fork() in userland.

        // Continue the original process
        self.orig.attach()?;
        self.orig.wait_for_signal(signal::Signal::SIGSTOP)?;
        self.orig.resume()?;
        self.orig.wait_for_signal(signal::Signal::SIGSTOP)?;

        // Start the syscall slave
        self.slave = Some(self.start_syscall_slave()?);

        // Find a location unused in both processes where we can safely map the syscall instruction
        // in the new process
        let memory_maps = self.orig.get_memory_maps()?;
        let mut slave_memory_maps = self.slave.as_ref().unwrap().get_memory_maps()?;
        self.syscall_page_location = self
            .find_location_for_syscall_page(&memory_maps, &slave_memory_maps)
            .context("Failed to find location for syscall page")?;
        log!("Found free space at {:x}", self.syscall_page_location);

        // We want to execute some syscalls in the original process. We don't want to accidentally
        // execute user code insecurely, and we don't really want to handle callbacks unless
        // necessary, so we adopt the seccomp filter so that it passes whatever we want without
        // resorting to ptrace. So far, this amounts to limited mmap and prctl support.

        Self::add_syscall_page(&mut self.orig, self.syscall_page_location)?;
        Self::add_syscall_page(self.slave.as_mut().unwrap(), self.syscall_page_location)?;
        log!("Placed syscall pages");

        // Make sure we don't accidentally munmap the syscall page in the slave
        slave_memory_maps.insert(
            slave_memory_maps.partition_point(|map| map.base < self.syscall_page_location),
            tracing::MemoryMap {
                base: self.syscall_page_location,
                end: self.syscall_page_location + 4096,
                ..Default::default()
            },
        );

        // TODO: actually copy stuff

        log!("Suspend finished in {:?}", self.started.elapsed());

        // proc.runner.
        Ok(())
    }

    fn add_syscall_page(proc: &mut tracing::TracedProcess, location: usize) -> Result<()> {
        // mmap an rwx page
        proc.exec_syscall(
            (
                libc::SYS_mmap,
                location,
                4096,
                libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED,
                -1,
                0,
            ),
            false,
        )
        .context("Failed to mmap syscall page")?;

        // Configure syscall page
        proc.write_memory(location, include_bytes!("../../target/syscall_loop.bin"))
            .context("Failed to write syscall page")?;
        proc.set_instruction_pointer(location)?;

        Ok(())
    }

    fn start_syscall_slave(&mut self) -> Result<tracing::TracedProcess> {
        log!("Starting slave");

        // Pass pidfd to self
        let pidfd =
            system::open_pidfd(nix::unistd::getpid()).context("Failed to get pidfd of self")?;

        let (theirs, mut ours) = crossmist::channel().context("Failed to create a pipe")?;
        let slave_process = prefork_slave
            .spawn(theirs, pidfd)
            .context("Failed to spawn the child")?;
        let slave_pid = Pid::from_raw(slave_process.id());

        // The child will either exit or trigger SIGTRAP on execve() to syscall_slave due to ptrace
        let wait_status =
            wait::waitpid(slave_pid, None).context("Failed to waitpid for process")?;
        match wait_status {
            wait::WaitStatus::Exited(_, _) => {
                bail!(
                    "{}",
                    ours.recv()
                        .context("Failed to read an error from the child")?
                        .context("The child terminated but did not report any error")?
                );
            }
            wait::WaitStatus::Stopped(_, signal::Signal::SIGTRAP) => {}
            _ => {
                bail!("waitpid returned unexpected status at syscall_slave: {wait_status:?}");
            }
        }
        tracing::TracedProcess::new_external(slave_pid, true)
    }

    fn find_location_for_syscall_page(
        &self,
        memory_maps: &[tracing::MemoryMap],
        slave_memory_maps: &[tracing::MemoryMap],
    ) -> Result<usize> {
        let mmap_min_addr = std::fs::read_to_string("/proc/sys/vm/mmap_min_addr")
            .context("Failed to read /proc/sys/vm/mmap_min_addr")?
            .trim()
            .parse()
            .context("Failed to parse /proc/sys/vm/mmap_min_addr")?;

        let mut location = mmap_min_addr;
        let mut i = 0;
        let mut j = 0;
        loop {
            while i < memory_maps.len() && location >= memory_maps[i].end {
                i += 1;
            }
            while j < slave_memory_maps.len() && location >= slave_memory_maps[j].end {
                j += 1;
            }
            if i < memory_maps.len() && location >= memory_maps[i].base {
                location = memory_maps[i].end;
            } else if j < slave_memory_maps.len() && location >= slave_memory_maps[j].base {
                location = slave_memory_maps[j].end;
            } else {
                return Ok(location);
            }
        }
    }
}

#[crossmist::func]
fn prefork_slave(mut pipe: crossmist::Sender<String>, suspender_pidfd: OwnedFd) {
    let result: Result<()> = try {
        // We don't want to bother about emulating setsid() in userspace fork, so use it by default
        nix::unistd::setsid().context("Failed to setsid")?;

        // Disable CLOEXEC for suspender_pidfd, as we want the syscall slave to use it. Also, we
        // want a fixed fd, and we don't need stdin, so using 0 works.
        unistd::dup2(suspender_pidfd.as_raw_fd(), SUSPENDER_PIDFD_FIXED_FD)
            .context("Failed to dup2 suspender_pidfd")?;
        let mut flags = fcntl::FdFlag::from_bits_truncate(
            fcntl::fcntl(SUSPENDER_PIDFD_FIXED_FD, fcntl::FcntlArg::F_GETFD)
                .expect("Failed to F_GETFD"),
        );
        flags &= !fcntl::FdFlag::FD_CLOEXEC;
        fcntl::fcntl(SUSPENDER_PIDFD_FIXED_FD, fcntl::FcntlArg::F_SETFD(flags))
            .expect("Failed to F_SETFD");

        // memfd should be created before applying seccomp filter
        let syscall_slave = system::make_memfd(
            "syscall_slave",
            include_bytes!("../../target/syscall_slave"),
        )?;

        // Perform as many lockdown operations as possible here, rather than via ptrace later. This
        // is less error-prone, more efficient, and also allows us to reuse code. However, we don't
        // drop privileges because we don't want the user to interact with us in any way.
        sandbox::set_no_new_privs()?;
        timens::disable_native_instructions()
            .context("Failed to disable native timens instructions")?;
        ptrace::traceme().context("Failed to ptrace(PTRACE_TRACEME)")?;
        tracing::apply_seccomp_filter(false).context("Failed to apply seccomp filter")?;
        unistd::fexecve::<&CStr, &CStr>(
            syscall_slave.as_raw_fd(),
            &[CStr::from_bytes_with_nul(b"syscall_slave\0").unwrap()],
            &[],
        )
        .context("execv failed")?;
    };

    if let Err(e) = result {
        pipe.send(&format!("{e:?}"))
            .expect("Failed to report error to parent");
    }
}
