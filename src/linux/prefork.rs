use crate::{
    linux::{ids, reaper, sandbox, system, timens, tracing},
    log,
};
use anyhow::{anyhow, bail, ensure, Context, Result};
use crossmist::Object;
use nix::{
    fcntl, libc,
    libc::{c_void, dev_t, itimerval, off_t, stack_t},
    sys::{ptrace, signal, stat, wait},
    unistd,
    unistd::Pid,
};
use std::cell::{Cell, RefCell};
use std::collections::HashMap;
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
    on_after_fork_syscalls: Vec<[usize; 7]>,
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
const ORIG_VM_FIXED_FD: RawFd = 2;

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
                // TODO: this should probably return the real ppid
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
                let gid = fd_stat.st_gid;
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
            on_after_fork_syscalls: Vec::new(),
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
        log!("Found free space at 0x{:x}", self.syscall_page_location);

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

        // TODO: we'd better remove this restriction
        self.ensure_no_pending_signals()
            .context("Failed to ensure there are no pending signals")?;

        // Unmap everything but [vsyscall], which cannot be unmapped (and we don't want to unmap it
        // anyway, as it is located at the same address in every process), and the syscall page
        self.unmap_garbage_in_slave(&slave_memory_maps)?;

        // Copy all state
        self.copy_maps(&memory_maps)
            .context("Failed to copy maps")?;
        self.copy_thp_options()
            .context("Failed to copy transparent huge pages options")?;
        self.copy_mm_options()
            .context("Failed to copy mm options")?;
        self.copy_cwd().context("Failed to copy cwd")?;
        self.copy_umask().context("Failed to copy umask")?;
        self.copy_tid_address()
            .context("Failed to copy tid address")?;
        self.copy_sigaltstack()
            .context("Failed to copy sigaltstack")?;
        self.copy_arch_prctl_options()
            .context("Failed to copy arch_prctl options")?;
        self.copy_personality()
            .context("Failed to copy personality")?;
        self.copy_resource_limits()
            .context("Failed to copy resource limits")?;
        self.copy_robust_list()
            .context("Failed to copy robust futex list")?;
        self.copy_itimers()
            .context("Failed to copy interval timers")?;
        self.copy_rseq()
            .context("Failed to copy restartable sequence")?;
        self.copy_fds().context("Failed to copy file descriptors")?;
        self.copy_timers().context("Failed to copy timers")?;
        self.copy_signal_handlers()
            .context("Failed to copy signal handlers")?;
        self.copy_signal_mask()
            .context("Failed to copy signal mask")?;

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

    fn slave_syscall<Args: tracing::SyscallArgs>(&mut self, args: Args) -> Result<isize>
    where
        [(); Args::N]:,
    {
        self.slave.as_mut().unwrap().exec_syscall(args, false)
    }

    fn slave_syscall_after_fork<Args: tracing::SyscallArgs>(&mut self, args: Args)
    where
        [(); Args::N]:,
    {
        let mut ext_args = [0; 7];
        ext_args[..Args::N].copy_from_slice(&args.to_usize_slice());
        self.on_after_fork_syscalls.push(ext_args)
    }

    fn ensure_no_pending_signals(&mut self) -> Result<()> {
        self.orig.exec_syscall(
            (libc::SYS_rt_sigpending, self.syscall_page_location + 128, 8),
            false,
        )?;
        if self.orig.read_word(self.syscall_page_location + 128)? != 0 {
            bail!("sunwalker cannot suspend processes with pending signals");
        }
        Ok(())
    }

    fn unmap_garbage_in_slave(&mut self, slave_memory_maps: &[tracing::MemoryMap]) -> Result<()> {
        log!("Unmapping unused pages in slave");
        let syscall_page_location = self.syscall_page_location;
        for maps in slave_memory_maps
            .split(|map| map.desc == "[vsyscall]" || map.base == syscall_page_location)
        {
            if maps.is_empty() {
                continue;
            }
            let base = maps[0].base;
            let end = maps.last().unwrap().end;
            self.slave_syscall((libc::SYS_munmap, base, end - base))
                .with_context(|| format!("Failed to munmap {:x}-{:x}", base, end))?;
        }
        Ok(())
    }

    fn copy_maps(&mut self, memory_maps: &[tracing::MemoryMap]) -> Result<()> {
        log!("Copying memory maps");

        {
            // Pass fd to memory of the original process
            let memory_fd = self.slave_syscall((
                libc::SYS_pidfd_getfd,
                SUSPENDER_PIDFD_FIXED_FD,
                self.orig.get_mem().as_raw_fd(),
                0,
            ))?;

            // We need this fd to be < 3 so that it doesn't collide with orig's fds, because we need it
            // after fork
            self.slave_syscall((libc::SYS_dup2, memory_fd, ORIG_VM_FIXED_FD))?;
            self.slave_syscall((libc::SYS_close, memory_fd))?;
        }

        let mut open_fds_interval = None;

        let mut fd_by_devino = HashMap::new();

        // [vsyscall] is the same in all processes (and located at the same address), so we neither
        // munmap nor mmap it (we can't do that, anyway). [vvar] and [vdso] have to be mmapped and
        // populated via arch_prctl rather than manually.
        const SPECIAL_MAPS: [&str; 3] = ["[vsyscall]", "[vvar]", "[vdso]"];

        // Shared memory is always backed by a writable file (anonymous mappings are backed by
        // /dev/zero), of which we only allow a short idempotent whitelist. Out of those, /dev/zero
        // is the only file that can be mmap'ed. Therefore, we can just mmap (and populate) shared
        // memory on every fork.

        // One problem is that two virtual addresses can be mmapped to the same physical address,
        // e.g. if we do memfd_create() and then mmap() it at two addresses. Luckily, we have
        // disabled memfd_create() in prefork mode, so that doesn't bother us.

        for map in memory_maps {
            if SPECIAL_MAPS.contains(&map.desc.as_str()) {
                continue;
            }

            let mut flags = libc::MAP_FIXED;
            if map.desc == "[stack]" {
                // FIXME: This assumes that a) only [stack] uses MAP_GROWSDOWN, b) no one has
                // disabled MAP_GROWSDOWN on [stack]. This is the case for most runtimes, but is
                // horrendously broken. We should parse /proc/<pid>/smaps instead. The same applies
                // to MAP_STACK. Also, they say that MAP_GROWSDOWN'ing a new page is not quite the
                // same thing as what the kernel does when allocating the main stack, so we should
                // figure that out.
                flags |= libc::MAP_GROWSDOWN | libc::MAP_STACK;
            }

            if map.shared {
                flags |= libc::MAP_SHARED;

                // Map memory (after fork)
                self.slave_syscall_after_fork((
                    libc::SYS_mmap,
                    map.base,
                    map.end - map.base,
                    libc::PROT_READ | libc::PROT_WRITE, // for pread64
                    flags,
                    -1,
                    0, // TODO: handle non-zero offset
                ));
            } else {
                flags |= libc::MAP_PRIVATE;

                let fd;
                if map.inode == 0 {
                    fd = -1;
                    flags |= libc::MAP_ANONYMOUS;
                } else {
                    let file = self.orig.open_map_file(map.base, map.end)?;

                    // Don't open many fd's to one file in the slave process -- this costs us
                    // precious ptrace() calls
                    let file_stat =
                        stat::fstat(file.as_raw_fd()).context("Failed to stat map file")?;
                    let devino = (file_stat.st_dev, file_stat.st_ino);

                    match fd_by_devino.get(&devino) {
                        Some(fd1) => fd = *fd1,
                        None => {
                            fd = self.slave_syscall((
                                libc::SYS_pidfd_getfd,
                                SUSPENDER_PIDFD_FIXED_FD,
                                file.as_raw_fd(),
                                0,
                            ))?;
                            fd_by_devino.insert(devino, fd);
                            open_fds_interval =
                                Some((open_fds_interval.map(|(from, _)| from).unwrap_or(fd), fd));
                        }
                    };
                }

                // Map memory
                self.slave_syscall((
                    libc::SYS_mmap,
                    map.base,
                    map.end - map.base,
                    libc::PROT_READ | libc::PROT_WRITE, // for pread64
                    flags,
                    fd,
                    map.offset,
                ))?;
            }

            // Don't change pages protection before dropping permissions so that we don't
            // accidentally execute user code under real root. Oof.
        }

        // Populate private maps
        for maps in memory_maps
            .split(|map| SPECIAL_MAPS.contains(&map.desc.as_str()))
            .flat_map(|maps| maps.split(|map| map.shared))
            .flat_map(|maps| maps.group_by(|a, b| a.end == b.base))
        {
            let base = maps[0].base;
            let end = maps.last().unwrap().end;
            self.slave_syscall((libc::SYS_pread64, ORIG_VM_FIXED_FD, base, end - base, base))?;
        }

        // Populate shared maps (after fork)
        for maps in memory_maps
            .split(|map| SPECIAL_MAPS.contains(&map.desc.as_str()))
            .flat_map(|maps| maps.split(|map| !map.shared))
            .flat_map(|maps| maps.group_by(|a, b| a.end == b.base))
        {
            let base = maps[0].base;
            let end = maps.last().unwrap().end;
            self.slave_syscall_after_fork((
                libc::SYS_pread64,
                ORIG_VM_FIXED_FD,
                base,
                end - base,
                base,
            ));
        }

        // Fix protection (after fork)
        for maps in memory_maps
            .split(|map| SPECIAL_MAPS.contains(&map.desc.as_str()))
            .flat_map(|maps| maps.group_by(|a, b| a.end == b.base && a.prot == b.prot))
        {
            let base = maps[0].base;
            let end = maps.last().unwrap().end;
            let prot = maps[0].prot;
            if prot != libc::PROT_READ | libc::PROT_WRITE {
                self.slave_syscall_after_fork((libc::SYS_mprotect, base, end - base, prot));
            }
        }

        if let Some((from, to)) = open_fds_interval {
            self.slave_syscall((libc::SYS_close_range, from, to, 0))?;
        }

        // Map [vvar] and [vdso]. FIXME: one could theoretically unmap a part of [vvar]/[vdso],
        // which we don't replicate correctly.
        let vdso_base = memory_maps
            .iter()
            .find(|map| map.desc == "[vvar]")
            .context("No [vvar] map found")?
            .base;
        const ARCH_MAP_VDSO_64: i32 = 0x2003;
        self.slave_syscall((libc::SYS_arch_prctl, ARCH_MAP_VDSO_64, vdso_base))?;

        Ok(())
    }

    fn copy_thp_options(&mut self) -> Result<()> {
        let thp_disable = self.orig.exec_syscall(
            (libc::SYS_prctl, libc::PR_GET_THP_DISABLE, 0, 0, 0, 0),
            false,
        )?;
        if thp_disable != 0 {
            log!("Disabling transparent huge pages");
            self.slave_syscall((
                libc::SYS_prctl,
                libc::PR_SET_THP_DISABLE,
                thp_disable,
                0,
                0,
                0,
            ))?;
        }
        Ok(())
    }

    fn copy_mm_options(&mut self) -> Result<()> {
        log!("Copying mm options");

        let stat = self.orig.get_stat()?;
        let brk = self.orig.exec_syscall((libc::SYS_brk, 0), false)? as usize;

        let map = prctl_mm_map {
            start_code: stat.start_code,
            end_code: stat.end_code,
            start_data: stat.start_data,
            end_data: stat.end_data,
            start_brk: stat.start_brk,
            brk,
            start_stack: stat.start_stack,
            arg_start: stat.arg_start,
            arg_end: stat.arg_end,
            env_start: stat.env_start,
            env_end: stat.env_end,
            auxv: 0,
            auxv_size: 0,
            exe_fd: u32::MAX,
        };
        self.slave
            .as_ref()
            .unwrap()
            .write_memory(self.syscall_page_location + 128, unsafe {
                &std::mem::transmute::<prctl_mm_map, [u8; std::mem::size_of::<prctl_mm_map>()]>(map)
            })?;
        self.slave_syscall((
            libc::SYS_prctl,
            libc::PR_SET_MM,
            libc::PR_SET_MM_MAP,
            self.syscall_page_location + 128,
            std::mem::size_of::<prctl_mm_map>(),
            0,
        ))?;

        Ok(())
    }

    fn copy_cwd(&mut self) -> Result<()> {
        log!("Copying cwd");

        let cwd = self.orig.open_cwd()?;
        let cwd_fd = self.slave_syscall((
            libc::SYS_pidfd_getfd,
            SUSPENDER_PIDFD_FIXED_FD,
            cwd.as_raw_fd(),
            0,
        ))?;
        self.slave_syscall((libc::SYS_fchdir, cwd_fd))?;
        self.slave_syscall((libc::SYS_close, cwd_fd))?;
        Ok(())
    }

    fn copy_umask(&mut self) -> Result<()> {
        log!("Copying umask");
        let umask = self.orig.exec_syscall((libc::SYS_umask, 0), false)?;
        self.slave_syscall((libc::SYS_umask, umask))?;
        Ok(())
    }

    fn copy_tid_address(&mut self) -> Result<()> {
        log!("Copying TID address");
        self.orig.exec_syscall(
            (
                libc::SYS_prctl,
                libc::PR_GET_TID_ADDRESS,
                self.syscall_page_location + 128,
            ),
            false,
        )?;
        let clear_child_tid = self.orig.read_word(self.syscall_page_location + 128)?;
        self.slave_syscall((libc::SYS_set_tid_address, clear_child_tid))?;
        Ok(())
    }

    fn copy_sigaltstack(&mut self) -> Result<()> {
        log!("Copying sigaltstack");
        self.orig.exec_syscall(
            (libc::SYS_sigaltstack, 0, self.syscall_page_location + 128),
            false,
        )?;
        let mut stack = unsafe { std::mem::zeroed::<stack_t>() };
        self.orig
            .read_memory(self.syscall_page_location + 128, unsafe {
                std::slice::from_raw_parts_mut(
                    &mut stack as *mut stack_t as *mut u8,
                    std::mem::size_of::<stack_t>(),
                )
            })?;
        if stack.ss_flags & libc::SS_DISABLE == 0 {
            self.slave.as_ref().unwrap().write_memory(
                self.syscall_page_location + 128,
                unsafe {
                    std::slice::from_raw_parts(
                        &stack as *const stack_t as *const u8,
                        std::mem::size_of::<stack_t>(),
                    )
                },
            )?;
            self.slave_syscall((libc::SYS_sigaltstack, self.syscall_page_location + 128, 0))?;
        }
        Ok(())
    }

    fn copy_arch_prctl_options(&mut self) -> Result<()> {
        log!("Copying arch_prctl options");

        // Bases of fs/gs
        const ARCH_SET_GS: i32 = 0x1001;
        const ARCH_SET_FS: i32 = 0x1002;
        const ARCH_GET_FS: i32 = 0x1003;
        const ARCH_GET_GS: i32 = 0x1004;
        for (get, set) in [(ARCH_GET_FS, ARCH_SET_FS), (ARCH_GET_GS, ARCH_SET_GS)] {
            self.orig.exec_syscall(
                (libc::SYS_arch_prctl, get, self.syscall_page_location + 128),
                false,
            )?;
            let value = self.orig.read_word(self.syscall_page_location + 128)?;
            self.slave_syscall((libc::SYS_arch_prctl, set, value))?;
        }

        // Whether cpuid is enabled
        const ARCH_GET_CPUID: i32 = 0x1011;
        const ARCH_SET_CPUID: i32 = 0x1012;
        let cpuid = self
            .orig
            .exec_syscall((libc::SYS_arch_prctl, ARCH_GET_CPUID, 0), false)?;
        if cpuid == 0 {
            self.slave_syscall((libc::SYS_arch_prctl, ARCH_SET_CPUID, 0))?;
        }

        Ok(())
    }

    fn copy_personality(&mut self) -> Result<()> {
        // Holy echopraxia
        log!("Copying personality");
        let personality = self
            .orig
            .exec_syscall((libc::SYS_personality, 0xffffffffu32), false)?;
        if personality != 0 {
            self.slave_syscall((libc::SYS_personality, personality))?;
        }
        Ok(())
    }

    fn copy_resource_limits(&mut self) -> Result<()> {
        log!("Copying resource limits");
        // Ignore:
        // - RLIMIT_CORE, as we disable core dumps in the controller,
        // - RLIMIT_RSS, which does nothing in modern kernels.
        // TODO: RLIMIT_CPU is likely to be reset after manually forking the process and has to be
        // updated or spent
        // TODO: Reset user-specific limits after the process is run so that they are not applied to
        // other runs
        for resource in [
            libc::RLIMIT_AS,
            libc::RLIMIT_CPU,
            libc::RLIMIT_DATA,
            libc::RLIMIT_FSIZE,
            libc::RLIMIT_LOCKS,
            libc::RLIMIT_MEMLOCK,
            libc::RLIMIT_MSGQUEUE,
            libc::RLIMIT_NICE,
            libc::RLIMIT_NOFILE,
            libc::RLIMIT_NPROC,
            libc::RLIMIT_RTPRIO,
            libc::RLIMIT_RTTIME,
            libc::RLIMIT_SIGPENDING,
            libc::RLIMIT_STACK,
        ] {
            unsafe {
                let mut limit = std::mem::MaybeUninit::uninit();
                if libc::prlimit(
                    self.orig.get_pid().as_raw(),
                    resource,
                    std::ptr::null(),
                    limit.as_mut_ptr(),
                ) == -1
                {
                    return Err(std::io::Error::last_os_error())
                        .context("Failed to get resource limit of original process");
                }
                if libc::prlimit(
                    self.slave.as_ref().unwrap().get_pid().as_raw(),
                    resource,
                    limit.as_ptr(),
                    std::ptr::null_mut(),
                ) == -1
                {
                    return Err(std::io::Error::last_os_error())
                        .context("Failed to set resource limit of slave process");
                }
            }
        }

        Ok(())
    }

    fn copy_robust_list(&mut self) -> Result<()> {
        log!("Copying robust list");
        let mut head = std::ptr::null::<c_void>();
        let mut len = 0usize;
        if unsafe {
            libc::syscall(
                libc::SYS_get_robust_list,
                self.orig.get_pid().as_raw(),
                &mut head,
                &mut len,
            )
        } == -1
        {
            return Err(std::io::Error::last_os_error())
                .context("Failed to get robust futex list of original process");
        }
        self.slave_syscall((libc::SYS_set_robust_list, head, len))
            .context("Failed to set robust futex list of slave process")?;
        Ok(())
    }

    fn copy_itimers(&mut self) -> Result<()> {
        log!("Copying itimers");
        // This also copies alarm(2)
        for itimer in [libc::ITIMER_REAL, libc::ITIMER_VIRTUAL, libc::ITIMER_PROF] {
            self.orig.exec_syscall(
                (
                    libc::SYS_getitimer,
                    itimer,
                    self.syscall_page_location + 128,
                ),
                false,
            )?;
            let mut value = [0u8; std::mem::size_of::<itimerval>()];
            self.orig
                .read_memory(self.syscall_page_location + 128, &mut value)?;
            if value == [0u8; std::mem::size_of::<itimerval>()] {
                continue;
            }
            self.slave
                .as_ref()
                .unwrap()
                .write_memory(self.syscall_page_location + 128, &value)?;
            self.slave_syscall((
                libc::SYS_setitimer,
                itimer,
                self.syscall_page_location + 128,
                0,
            ))?;
        }
        Ok(())
    }

    fn copy_rseq(&mut self) -> Result<()> {
        #[allow(non_upper_case_globals)]
        const SYS_rseq: i32 = 334;

        log!("Copying rseq");

        // We don't have to handle the case of suspending inside a restartable sequence because we
        // only suspend during syscalls, and running syscalls while inside an rseq is undefined
        // behavior.
        // XXX: If we ever support suspending outside a syscall, this code should be rewritten
        let rseq = self.orig.get_rseq_configuration()?;
        self.slave_syscall((
            SYS_rseq,
            rseq.rseq_abi_pointer,
            rseq.rseq_abi_size,
            rseq.flags,
            rseq.signature,
        ))?;
        Ok(())
    }

    fn copy_fds(&mut self) -> Result<()> {
        log!("Copying file descriptors");

        let orig_pidfd = system::open_pidfd(self.orig.get_pid())
            .context("Failed to get pidfd of the original process")?;

        for orig_fd in self.orig.list_fds()? {
            if orig_fd < 3 {
                continue;
            }

            let fd_info = self.orig.get_fd_info(orig_fd)?;

            let slave_fd;

            if let Some(count) = fd_info.get("eventfd-count") {
                // Clone an eventfd
                let count: u32 = count.parse().context("'eventfd-count' is not a number")?;
                let mut flags = i32::from_str_radix(
                    fd_info
                        .get("flags")
                        .context("'flags' missing from an eventfd fdinfo")?,
                    16,
                )
                .context("'flags' is not a hexadecimal number")?;
                flags &= !libc::O_ACCMODE;
                // FIXME: move this to after fork
                slave_fd = self.slave_syscall((libc::SYS_eventfd, count, flags))? as RawFd;
            } else {
                // Clone a normal fd
                let fd = system::pidfd_getfd(orig_pidfd.as_raw_fd(), orig_fd)?;
                slave_fd = self.slave_syscall((
                    libc::SYS_pidfd_getfd,
                    SUSPENDER_PIDFD_FIXED_FD,
                    fd.as_raw_fd(),
                    0,
                ))? as RawFd;
                // FIXME: this should open another file description
            }

            // Make the two fds match
            ensure!(slave_fd <= orig_fd, "Unexpected allocated fd");
            if slave_fd < orig_fd {
                self.slave_syscall((libc::SYS_dup2, slave_fd, orig_fd))?;
                self.slave_syscall((libc::SYS_close, slave_fd))?;
            }

            eprintln!("{orig_fd} {slave_fd}");
        }

        Ok(())
    }

    fn copy_timers(&mut self) -> Result<()> {
        log!("Copying timers");

        let mut timers = self.orig.get_timers()?;
        timers.sort_unstable_by_key(|timer| timer.id);

        let mut next_timer_id = 0;

        let mut add_timer = |timer: &tracing::Timer| -> Result<()> {
            // Fucking libc
            let mut sigevent: libc::sigevent = unsafe { std::mem::zeroed() };
            sigevent.sigev_notify = timer.notify.0;
            sigevent.sigev_signo = timer.signal;
            sigevent.sigev_value.sival_ptr = timer.sigev_value as *mut _;
            sigevent.sigev_notify_thread_id = timer.notify.1.as_raw();
            self.slave.as_ref().unwrap().write_memory(
                self.syscall_page_location + 128,
                unsafe {
                    &std::mem::transmute::<
                        libc::sigevent,
                        [u8; std::mem::size_of::<libc::sigevent>()],
                    >(sigevent)
                },
            )?;
            self.slave
                .as_ref()
                .unwrap()
                .write_word(self.syscall_page_location + 256, 0)?;
            self.slave_syscall((
                libc::SYS_timer_create,
                timer.clock_id,
                self.syscall_page_location + 128,
                self.syscall_page_location + 256,
            ))?;
            let timer_id = self
                .slave
                .as_ref()
                .unwrap()
                .read_word(self.syscall_page_location + 256)? as i32;
            if timer.id != timer_id {
                bail!(
                    "Expected to create timer #{} actually created #{timer_id}",
                    timer.id
                );
            }
            Ok(())
        };

        for timer in &timers {
            while timer.id > next_timer_id {
                // Create a temporary unused timer to fill the void so that our timer gets the right
                // ID
                add_timer(&tracing::Timer {
                    id: next_timer_id,
                    signal: 0,
                    sigev_value: 0,
                    notify: (libc::SIGEV_NONE, Pid::from_raw(0)),
                    clock_id: libc::CLOCK_REALTIME,
                })?;
                next_timer_id += 1;
            }
            add_timer(&timer)?;
            next_timer_id += 1;
        }

        // Remove temporary timers
        next_timer_id = 0;
        for timer in timers {
            while timer.id > next_timer_id {
                // Create a temporary unused timer to fill the void so that our timer gets the right
                // ID
                self.slave_syscall((libc::SYS_timer_delete, next_timer_id))?;
                next_timer_id += 1;
            }
            next_timer_id += 1;
        }

        Ok(())
    }

    fn copy_signal_handlers(&mut self) -> Result<()> {
        log!("Copying signal handlers");

        for signum in 1..=64 {
            if signum == libc::SIGKILL || signum == libc::SIGSTOP {
                continue;
            }

            self.orig.exec_syscall(
                (
                    libc::SYS_rt_sigaction,
                    signum,
                    0,
                    self.syscall_page_location + 128,
                    8,
                ),
                false,
            )?;
            let mut action = [0u8; std::mem::size_of::<libc::sigaction>()];
            self.orig
                .read_memory(self.syscall_page_location + 128, &mut action)?;
            self.slave
                .as_ref()
                .unwrap()
                .write_memory(self.syscall_page_location + 128, &action)?;
            self.slave_syscall((
                libc::SYS_rt_sigaction,
                signum,
                self.syscall_page_location + 128,
                0,
                8,
            ))?;
        }

        Ok(())
    }

    fn copy_signal_mask(&mut self) -> Result<()> {
        log!("Copying signal mask");

        self.orig.exec_syscall(
            (
                libc::SYS_rt_sigprocmask,
                libc::SIG_BLOCK,
                0,
                self.syscall_page_location + 128,
                8,
            ),
            false,
        )?;
        let sigset = self.orig.read_word(self.syscall_page_location + 128)?;
        self.slave
            .as_ref()
            .unwrap()
            .write_word(self.syscall_page_location + 128, sigset)?;
        self.slave_syscall((
            libc::SYS_rt_sigprocmask,
            libc::SIG_SETMASK,
            self.syscall_page_location + 128,
            0,
            8,
        ))?;
        Ok(())
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
