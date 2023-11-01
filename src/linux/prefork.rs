use crate::{
    linux::{ids, reaper, sandbox, system, timens, tracing, rootfs},
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
use std::ops::Range;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::time::Instant;

use super::tracing::MemoryMap;

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
    master: Option<tracing::TracedProcess>,
    parasite_location: usize,
    registers: tracing::Registers,
    rseq_info: Option<RSeqInfo>,
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

#[repr(C)]
struct ParasiteStartInformation {
    orig_pid: i32,
    relocate_from: usize,
    relocate_to: usize,
    prog_size: usize,
    rseq_info: Option<RSeqInfo>,
}

const SUSPENDER_PIDFD_FIXED_FD: RawFd = 1;
// const ORIG_VM_FIXED_FD: RawFd = 2;

struct ParasiteInfo {
    prog_size: usize,
    prog_file_offset: usize,
    checkpoint_vma: usize,
    start_vma: usize,
    start_information_vma: usize,
}

const PARASITE_ELF: &[u8] = include_bytes!("../../target/parasite");
const PARASITE_INFO: ParasiteInfo = include!("../../target/parasite.info");

#[repr(C)]
struct rseq_abi {
    cpu_id_start: u32,
    cpu_id: u32,
    rseq_cs: u64,
    flags: u32,
    node_id: u32,
    mm_cid: u32,
}

#[repr(C)]
struct rseq_cs {
    version: u32,
    flags: u32,
    start_ip: u64,
    post_commit_offset: u64,
    abort_ip: u64,
}

#[derive(Clone, Object)]
#[repr(C)]
pub struct RSeqInfo {
    rseq_abi_pointer: usize,
    rseq_abi_size: u32,
    flags: u32,
    signature: u32,
    rseq_cs: usize,
}

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

        // It's important to get the kernel messing with IP due to rseq out of the way as fast as
        // possible
        let rseq_info = self.save_rseq_info(orig)?;

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
                rseq_info,
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

    fn save_rseq_info(&self, orig: &mut tracing::TracedProcess) -> Result<Option<RSeqInfo>> {
        // Check if IP is inside a restartable sequence. If it is, the kernel might jump to the
        // abort handler when we don't expect that to happen. Prevent this by resetting the
        // information about the critical section, if present.
        let rseq = orig.get_rseq_configuration().context("Failed to get rseq configuration")?;
        if rseq.rseq_abi_size == 0 {
            return Ok(None);
        }
        let rseq_cs_ptr = rseq.rseq_abi_pointer as usize + std::mem::offset_of!(rseq_abi, rseq_cs);
        let rseq_cs = orig.read_word(rseq_cs_ptr).context("Failed to read rseq CS pointer")?;
        if rseq_cs != 0 {
            orig.write_word(rseq_cs_ptr, 0).context("Failed to override rseq CS pointer to 0")?;
        }
        Ok(Some(RSeqInfo {
            rseq_abi_pointer: rseq.rseq_abi_pointer as usize,
            rseq_abi_size: rseq.rseq_abi_size,
            flags: rseq.flags,
            signature: rseq.signature,
            rseq_cs,
        }))
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
                    // Even if the file is not writable at the moment, the owner may change
                    // permissions later
                    true
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
        rseq_info: Option<RSeqInfo>,
        started: Instant,
    ) -> Result<Self> {
        Ok(Self {
            options,
            orig: tracing::TracedProcess::new_external(pid, true)?,
            master: None,
            parasite_location: 0,
            registers,
            rseq_info,
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

        // Start the master copy
        self.master = Some(self.start_master()?);

        // Find a location unused in both processes where we can safely map the syscall instruction
        // in the new process
        let memory_maps = self.orig.get_memory_maps()?;
        let mut master_memory_maps = self.master.as_ref().unwrap().get_memory_maps()?;
        self.parasite_location = self
            .find_location_for_parasite(&memory_maps, &master_memory_maps)
            .context("Failed to find location for syscall page")?;
        log!("Found free space at 0x{:x}", self.parasite_location);

        self.infect_orig()
            .context("Failed to infect original process")?;
        self.collect_info()
            .context("Failed to collect information")?;
        self.teleport_parasite_to_master(&master_memory_maps)
            .context("Failed to teleport parasite to master")?;

        let wait_status =
            wait::waitpid(self.master.as_ref().unwrap().get_pid(), None).context("Failed to waitpid for process")?;
        eprintln!("{wait_status:?}");

        // // Unmap everything but [vsyscall], which cannot be unmapped (and we don't want to unmap it
        // // anyway, as it is located at the same address in every process), and the syscall page
        // self.unmap_garbage_in_slave(&slave_memory_maps)?;

        // // Copy all state
        // self.copy_maps(&memory_maps)
        //     .context("Failed to copy maps")?;
        // self.copy_thp_options()
        //     .context("Failed to copy transparent huge pages options")?;
        // self.copy_mm_options()
        //     .context("Failed to copy mm options")?;
        // self.copy_cwd().context("Failed to copy cwd")?;
        // self.copy_umask().context("Failed to copy umask")?;
        // self.copy_tid_address()
        //     .context("Failed to copy tid address")?;
        // self.copy_sigaltstack()
        //     .context("Failed to copy sigaltstack")?;
        // self.copy_arch_prctl_options()
        //     .context("Failed to copy arch_prctl options")?;
        // self.copy_personality()
        //     .context("Failed to copy personality")?;
        // self.copy_resource_limits()
        //     .context("Failed to copy resource limits")?;
        // self.copy_robust_list()
        //     .context("Failed to copy robust futex list")?;
        // self.copy_itimers()
        //     .context("Failed to copy interval timers")?;
        // self.copy_rseq()
        //     .context("Failed to copy restartable sequence")?;
        // self.copy_fds().context("Failed to copy file descriptors")?;
        // self.copy_timers().context("Failed to copy timers")?;
        // self.copy_signal_handlers()
        //     .context("Failed to copy signal handlers")?;
        // self.copy_signal_mask()
        //     .context("Failed to copy signal mask")?;

        log!("Suspend finished in {:?}", self.started.elapsed());

        // proc.runner.
        Ok(())
    }

    // fn add_syscall_page(proc: &mut tracing::TracedProcess, location: usize) -> Result<()> {
    //     // mmap an rwx page
    //     proc.exec_syscall(
    //         (
    //             libc::SYS_mmap,
    //             location,
    //             4096,
    //             libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
    //             libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED,
    //             -1,
    //             0,
    //         ),
    //         false,
    //     )
    //     .context("Failed to mmap syscall page")?;

    //     // Configure syscall page
    //     proc.write_memory(location, include_bytes!("../../target/syscall_loop.bin"))
    //         .context("Failed to write syscall page")?;
    //     proc.set_instruction_pointer(location)?;

    //     Ok(())
    // }

    fn start_master(&mut self) -> Result<tracing::TracedProcess> {
        log!("Starting master copy");

        // Pass pidfd to self
        let pidfd =
            system::open_pidfd(nix::unistd::getpid()).context("Failed to get pidfd of self")?;

        let (theirs, mut ours) = crossmist::channel().context("Failed to create a pipe")?;
        let master_process = prefork_master
            .spawn(theirs, pidfd)
            .context("Failed to spawn the child")?;
        let master_pid = Pid::from_raw(master_process.id());

        // The child will either exit or trigger SIGTRAP on execve() to parasite due to ptrace
        let wait_status =
            wait::waitpid(master_pid, None).context("Failed to waitpid for process")?;
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
                bail!("waitpid returned unexpected status at parasite: {wait_status:?}");
            }
        }
        tracing::TracedProcess::new_external(master_pid, true)
    }

    fn find_location_for_parasite(
        &self,
        maps1: &[tracing::MemoryMap],
        maps2: &[tracing::MemoryMap],
    ) -> Result<usize> {
        let mmap_min_addr: usize = std::fs::read_to_string("/proc/sys/vm/mmap_min_addr")
            .context("Failed to read /proc/sys/vm/mmap_min_addr")?
            .trim()
            .parse()
            .context("Failed to parse /proc/sys/vm/mmap_min_addr")?;

        let mut location = mmap_min_addr.max(4096);
        let mut i = 0;
        let mut j = 0;
        loop {
            while i < maps1.len() && location >= maps1[i].end {
                i += 1;
            }
            while j < maps2.len() && location >= maps2[j].end {
                j += 1;
            }
            if i < maps1.len() && location + PARASITE_INFO.prog_size > maps1[i].base {
                location = maps1[i].end;
            } else if j < maps2.len() && location + PARASITE_INFO.prog_size > maps2[j].base {
                location = maps2[j].end;
            } else {
                return Ok(location);
            }
        }
    }

    fn infect_orig(&mut self) -> Result<()> {
        log!("Infecting original process");

        // mmap an rwx segment
        self.orig
            .exec_syscall(
                (
                    libc::SYS_mmap,
                    self.parasite_location,
                    PARASITE_INFO.prog_size,
                    libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED,
                    -1,
                    0,
                ),
                false,
            )
            .context("Failed to mmap parasite segment")?;

        // Load code
        self.orig
            .write_memory(
                self.parasite_location,
                &PARASITE_ELF[PARASITE_INFO.prog_file_offset
                    ..PARASITE_INFO.prog_file_offset + PARASITE_INFO.prog_size],
            )
            .context("Failed to write parasite segment")?;

        // Reset processor stack (direction flag, x87 state, etc.). This should prevent the original
        // process from configuring the CPU in a way the parasite doesn't expect
        let mut regs: tracing::Registers = unsafe { std::mem::zeroed() };
        regs.rip = (self.parasite_location + PARASITE_INFO.checkpoint_vma) as u64;
        // This relies on the fact that segment registers point at GDT, which is shared between all
        // processes
        unsafe {
            // NB: this could be a single instruction rather than mov to a general register followed
            // by a mov to memory, but that's a premature optimization
            std::arch::asm!("mov {}, cs", out(reg) regs.cs);
            std::arch::asm!("mov {}, ss", out(reg) regs.ss);
            std::arch::asm!("mov {}, ds", out(reg) regs.ds);
            std::arch::asm!("mov {}, es", out(reg) regs.es);
            std::arch::asm!("mov {}, fs", out(reg) regs.fs);
            std::arch::asm!("mov {}, gs", out(reg) regs.gs);
        }
        self.orig.set_registers(regs);

        let start_information = ParasiteStartInformation {
            orig_pid: self.orig.get_pid().as_raw(),
            relocate_from: 0,
            relocate_to: self.parasite_location,
            prog_size: PARASITE_INFO.prog_size,
            rseq_info: self.rseq_info.clone(),
        };
        self.orig.write_memory(
            self.parasite_location + PARASITE_INFO.start_information_vma,
            unsafe {
                &std::mem::transmute::<
                    ParasiteStartInformation,
                    [u8; std::mem::size_of::<ParasiteStartInformation>()],
                >(start_information)
            },
        )?;

        Ok(())
    }

    fn collect_info(&mut self) -> Result<()> {
        log!("Running parasite in original process");

        // We want the parasite to execute some syscalls in the original process. Unfortunately,
        // these syscalls include ones blocked by seccomp due to the nature of prefork, so we have
        // to explicitly allow them via ptrace.

        self.orig.init()?;
        self.orig.resume()?;

        // We must consider that at any point in time, a signal may arrive, delayed from the
        // original process. This is critical to get right, because we later copy memory from the
        // parasite in the original process into a process with effective root capabilities and
        // *execute* it. This means that we don't want *anything* from the original process to be
        // able to affect the parasite.

        loop {
            log!("Waiting for event");
            let wait_status =
                system::waitpid(Some(self.orig.get_pid()), system::WaitPidFlag::__WALL)
                    .context("Failed to waitpid")?;
            log!("Event in parasite: {wait_status:?}");
            match wait_status {
                system::WaitStatus::Exited(..) | system::WaitStatus::Signaled(..) => {
                    bail!("Unexpected exit from parasite")
                }
                system::WaitStatus::Stopped(..) => {
                    // Only treat SIGUSR1 as a teleport signal if it was sent explicitly, rather
                    // than triggered by any sort of delayed mechanism
                    let info = self.orig.get_signal_info()?;
                    const SI_USER: i32 = 0;
                    if info.si_signo == libc::SIGUSR1 && info.si_code == SI_USER {
                        break;
                    } else {
                        bail!("Unexpected stop in parasite");
                    }
                }
                system::WaitStatus::PtraceEvent(..) => self.orig.resume()?,
                _ => bail!("Unexpected status"),
            }
        }

        Ok(())
    }

    fn teleport_parasite_to_master(&mut self, memory_maps: &[MemoryMap]) -> Result<()> {
        log!("Initializing parasite in master");
        let current_parasite_map = memory_maps
            .iter()
            .find(|map| map.desc.is_empty())
            .context("Could not find current parasite mapping")?;
        log!("Current base is 0x{:x}", current_parasite_map.base);
        let start_information = ParasiteStartInformation {
            orig_pid: self.orig.get_pid().as_raw(),
            relocate_from: current_parasite_map.base,
            relocate_to: self.parasite_location,
            prog_size: current_parasite_map.end - current_parasite_map.base,
            rseq_info: self.rseq_info.clone(),
        };

        let master = self.master.as_mut().unwrap();
        master.write_memory(
            current_parasite_map.base + PARASITE_INFO.start_information_vma,
            unsafe {
                &std::mem::transmute::<
                    ParasiteStartInformation,
                    [u8; std::mem::size_of::<ParasiteStartInformation>()],
                >(start_information)
            },
        )?;
        master.resume()?;

        // After mremap, the code is no longer mapped
        master
            .wait_for_signal(signal::Signal::SIGSEGV)
            .context("Did not receive SIGSEGV after relocation")?;

        let regs = self
            .orig
            .get_registers()
            .context("Failed to get registers of original process")?;
        master.set_registers(regs);

        log!("Teleport complete, parasite now running in master");

        master.resume()?;

        Ok(())
    }

    // fn slave_syscall<Args: tracing::SyscallArgs>(&mut self, args: Args) -> Result<isize>
    // where
    //     [(); Args::N]:,
    // {
    //     self.slave.as_mut().unwrap().exec_syscall(args, false)
    // }

    // fn slave_syscall_after_fork<Args: tracing::SyscallArgs>(&mut self, args: Args)
    // where
    //     [(); Args::N]:,
    // {
    //     let mut ext_args = [0; 7];
    //     ext_args[..Args::N].copy_from_slice(&args.to_usize_slice());
    //     self.on_after_fork_syscalls.push(ext_args)
    // }

    // fn copy_fds(&mut self) -> Result<()> {
    //     log!("Copying file descriptors");

    //     let orig_pidfd = system::open_pidfd(self.orig.get_pid())
    //         .context("Failed to get pidfd of the original process")?;

    //     for orig_fd in self.orig.list_fds()? {
    //         if orig_fd < 3 {
    //             continue;
    //         }

    //         let fd_info = self.orig.get_fd_info(orig_fd)?;

    //         let slave_fd;

    //         if let Some(count) = fd_info.get("eventfd-count") {
    //             // Clone an eventfd
    //             let count: u32 = count.parse().context("'eventfd-count' is not a number")?;
    //             let mut flags = i32::from_str_radix(
    //                 fd_info
    //                     .get("flags")
    //                     .context("'flags' missing from an eventfd fdinfo")?,
    //                 16,
    //             )
    //             .context("'flags' is not a hexadecimal number")?;
    //             flags &= !libc::O_ACCMODE;
    //             // FIXME: move this to after fork
    //             slave_fd = self.slave_syscall((libc::SYS_eventfd, count, flags))? as RawFd;
    //         } else {
    //             // Clone a normal fd
    //             let fd = system::pidfd_getfd(orig_pidfd.as_raw_fd(), orig_fd)?;
    //             slave_fd = self.slave_syscall((
    //                 libc::SYS_pidfd_getfd,
    //                 SUSPENDER_PIDFD_FIXED_FD,
    //                 fd.as_raw_fd(),
    //                 0,
    //             ))? as RawFd;
    //             // FIXME: this should open another file description
    //         }

    //         // Make the two fds match
    //         ensure!(slave_fd <= orig_fd, "Unexpected allocated fd");
    //         if slave_fd < orig_fd {
    //             self.slave_syscall((libc::SYS_dup2, slave_fd, orig_fd))?;
    //             self.slave_syscall((libc::SYS_close, slave_fd))?;
    //         }

    //         eprintln!("{orig_fd} {slave_fd}");
    //     }

    //     Ok(())
    // }

    // fn copy_timers(&mut self) -> Result<()> {
    //     log!("Copying timers");

    //     let mut timers = self.orig.get_timers()?;
    //     timers.sort_unstable_by_key(|timer| timer.id);

    //     let mut next_timer_id = 0;

    //     let mut add_timer = |timer: &tracing::Timer| -> Result<()> {
    //         // Fucking libc
    //         let mut sigevent: libc::sigevent = unsafe { std::mem::zeroed() };
    //         sigevent.sigev_notify = timer.notify.0;
    //         sigevent.sigev_signo = timer.signal;
    //         sigevent.sigev_value.sival_ptr = timer.sigev_value as *mut _;
    //         sigevent.sigev_notify_thread_id = timer.notify.1.as_raw();
    //         self.slave.as_ref().unwrap().write_memory(
    //             self.parasite_location + 128,
    //             unsafe {
    //                 &std::mem::transmute::<
    //                     libc::sigevent,
    //                     [u8; std::mem::size_of::<libc::sigevent>()],
    //                 >(sigevent)
    //             },
    //         )?;
    //         self.slave
    //             .as_ref()
    //             .unwrap()
    //             .write_word(self.parasite_location + 256, 0)?;
    //         self.slave_syscall((
    //             libc::SYS_timer_create,
    //             timer.clock_id,
    //             self.parasite_location + 128,
    //             self.parasite_location + 256,
    //         ))?;
    //         let timer_id = self
    //             .slave
    //             .as_ref()
    //             .unwrap()
    //             .read_word(self.parasite_location + 256)? as i32;
    //         if timer.id != timer_id {
    //             bail!(
    //                 "Expected to create timer #{} actually created #{timer_id}",
    //                 timer.id
    //             );
    //         }
    //         Ok(())
    //     };

    //     for timer in &timers {
    //         while timer.id > next_timer_id {
    //             // Create a temporary unused timer to fill the void so that our timer gets the right
    //             // ID
    //             add_timer(&tracing::Timer {
    //                 id: next_timer_id,
    //                 signal: 0,
    //                 sigev_value: 0,
    //                 notify: (libc::SIGEV_NONE, Pid::from_raw(0)),
    //                 clock_id: libc::CLOCK_REALTIME,
    //             })?;
    //             next_timer_id += 1;
    //         }
    //         add_timer(&timer)?;
    //         next_timer_id += 1;
    //     }

    //     // Remove temporary timers
    //     next_timer_id = 0;
    //     for timer in timers {
    //         while timer.id > next_timer_id {
    //             // Create a temporary unused timer to fill the void so that our timer gets the right
    //             // ID
    //             self.slave_syscall((libc::SYS_timer_delete, next_timer_id))?;
    //             next_timer_id += 1;
    //         }
    //         next_timer_id += 1;
    //     }

    //     Ok(())
    // }

    // fn copy_signal_handlers(&mut self) -> Result<()> {
    //     log!("Copying signal handlers");

    //     for signum in 1..=64 {
    //         if signum == libc::SIGKILL || signum == libc::SIGSTOP {
    //             continue;
    //         }

    //         self.orig.exec_syscall(
    //             (
    //                 libc::SYS_rt_sigaction,
    //                 signum,
    //                 0,
    //                 self.parasite_location + 128,
    //                 8,
    //             ),
    //             false,
    //         )?;
    //         let mut action = [0u8; std::mem::size_of::<libc::sigaction>()];
    //         self.orig
    //             .read_memory(self.parasite_location + 128, &mut action)?;
    //         self.slave
    //             .as_ref()
    //             .unwrap()
    //             .write_memory(self.parasite_location + 128, &action)?;
    //         self.slave_syscall((
    //             libc::SYS_rt_sigaction,
    //             signum,
    //             self.parasite_location + 128,
    //             0,
    //             8,
    //         ))?;
    //     }

    //     Ok(())
    // }

    // fn copy_signal_mask(&mut self) -> Result<()> {
    //     log!("Copying signal mask");

    //     self.orig.exec_syscall(
    //         (
    //             libc::SYS_rt_sigprocmask,
    //             libc::SIG_BLOCK,
    //             0,
    //             self.parasite_location + 128,
    //             8,
    //         ),
    //         false,
    //     )?;
    //     let sigset = self.orig.read_word(self.parasite_location + 128)?;
    //     self.slave
    //         .as_ref()
    //         .unwrap()
    //         .write_word(self.parasite_location + 128, sigset)?;
    //     self.slave_syscall((
    //         libc::SYS_rt_sigprocmask,
    //         libc::SIG_SETMASK,
    //         self.parasite_location + 128,
    //         0,
    //         8,
    //     ))?;
    //     Ok(())
    // }
}

#[crossmist::func]
fn prefork_master(mut pipe: crossmist::Sender<String>, suspender_pidfd: OwnedFd) {
    let result: Result<()> = try {
        // We don't want to bother about emulating setsid() in userspace fork, so use it by default
        nix::unistd::setsid().context("Failed to setsid")?;

        // Disable CLOEXEC for suspender_pidfd, as we want the syscall slave to use it. Also, we
        // want a fixed fd.
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
        let parasite = system::make_memfd("parasite", PARASITE_ELF)?;

        // Perform as many lockdown operations as possible here, rather than via ptrace later. This
        // is less error-prone, more efficient, and also allows us to reuse code. However, we don't
        // drop privileges because we don't want the user to interact with us in any way.
        sandbox::set_no_new_privs()?;
        timens::disable_native_instructions()
            .context("Failed to disable native timens instructions")?;
        rootfs::enter_rootfs().context("Failed to enter rootfs")?;
        ptrace::traceme().context("Failed to ptrace(PTRACE_TRACEME)")?;
        tracing::apply_seccomp_filter(false).context("Failed to apply seccomp filter")?;
        unistd::fexecve::<&CStr, &CStr>(
            parasite.as_raw_fd(),
            &[CStr::from_bytes_with_nul(b"parasite\0").unwrap()],
            &[],
        )
        .context("execv failed")?;
    };

    if let Err(e) = result {
        pipe.send(&format!("{e:?}"))
            .expect("Failed to report error to parent");
    }
}
