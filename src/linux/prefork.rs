use crate::{
    linux::{cgroups, ids, string_table, system, timens, tracing, userns},
    log, syscall,
};
use anyhow::{anyhow, bail, ensure, Context, Result};
use crossmist::{Object, Sender};
use nix::{
    fcntl, libc,
    libc::{dev_t, mode_t, off_t, pid_t},
    sys::{prctl, ptrace, signal, stat, wait},
    unistd,
    unistd::Pid,
};
use std::cell::Cell;
use std::collections::{HashMap, HashSet};
use std::ffi::CStr;
use std::fs::File;
use std::io::{BufRead, BufReader, IoSlice};
use std::mem::MaybeUninit;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::{SocketAncillary, UnixStream};
use std::path::{Path, PathBuf};
use std::time::Instant;

pub struct PreForkManager {
    pub stdio_subst: File,
    stdio_subst_devino: (u64, u64),
    white_list_rdev: Vec<dev_t>,
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

enum State {
    NotStarted,
    Alive,
    WaitingOnOpen,
    Suspended(SuspendData),
}

pub struct SuspendData {
    master: tracing::TracedProcess,
    pub orig_pid: Pid,
    inject_location: usize,
    cwd: PathBuf,
    control_tx: UnixStream,
    registers: tracing::Registers,
    signal_mask: u64,
}

// MaybeUninit is used to avoid data leaks via padding
pub struct Suspender<'a> {
    orig: &'a mut tracing::TracedProcess,
    options: SuspendOptions,
    inject_location: usize,
    master: Option<tracing::TracedProcess>,
    transferred_fds: Vec<OwnedFd>,
    forbidden_transferred_fds: HashSet<RawFd>,
    stemcell_state: MaybeUninit<StemcellState>,
    control_tx: Option<UnixStream>,
    // rseq_info: Option<RSeqInfo>,
    // started: Instant,
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
    exe_fd: i32,
}

const PARASITE: &[u8] = include_bytes!("../../target/parasite.bin");
const PARASITE_SIZE: usize = include!("../../target/parasite.size");
const PARASITE_CONTEXTS: &[&str] = &include!("../../target/parasite.result_context_map.json");
const PARASITE_STATE_OFFSET: usize = include!("../../target/parasite.state");
// code + data, rounded to page size
const PARASITE_MEMORY_SIZE: usize = (PARASITE_SIZE + 4095) / 4096 * 4096;

const STEMCELL: &[u8] = include_bytes!("../../target/stemcell.stripped");
const STEMCELL_CONTEXTS: &[&str] = &include!("../../target/stemcell.result_context_map.json");
const STEMCELL_RELOCATIONS: &[usize] = &include!("../../target/stemcell.relocations");
const STEMCELL_STATE_OFFSET: usize = include!("../../target/stemcell.state");

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

#[repr(C)]
struct ArchPrctlOptions {
    fs_base: usize,
    gs_base: usize,
    cpuid_status: usize,
}

#[repr(C)]
struct ItimersState {
    real: libc::itimerval,
    virtual_: libc::itimerval,
    prof: libc::itimerval,
}

#[repr(C)]
struct kernel_sigaction {
    sa_handler: usize,
    sa_flags: u32,
    sa_restorer: usize,
    sa_mask: u64,
}

#[repr(C)]
struct ParasiteState {
    result: u64,
    alternative_stack: libc::stack_t,
    arch_prctl_options: ArchPrctlOptions,
    itimers: ItimersState,
    program_break: usize,
    pending_signals: u64,
    personality: usize,
    signal_handlers: [kernel_sigaction; 64],
    thp_options: usize,
    tid_address: usize,
    umask: libc::mode_t,
}

#[repr(C)]
struct StemcellState {
    result: u64,
    alternative_stack: libc::stack_t,
    arch_prctl_options: ArchPrctlOptions,
    file_descriptors: FileDescriptors,
    itimers: ItimersState,
    memory_maps: MemoryMaps,
    mm_options: prctl_mm_map,
    personality: usize,
    signal_handlers: [kernel_sigaction; 64],
    thp_options: usize,
    tid_address: usize,
    umask: mode_t,
    controlling_fd: RawFd,
}

// The default value of sysctl fs.nr_open = 1048576 is too large to allocate a static array for, so
// use a smaller value of 10000, which should be enough for most use cases of prefork
const MAX_FILE_DESCRIPTORS: usize = 10000;

#[repr(C)]
struct FileDescriptors {
    count: usize,
    fds: [SavedFd; MAX_FILE_DESCRIPTORS],
}

#[repr(C)]
struct SavedFd {
    fd: RawFd,
    flags: i32,
    kind: SavedFdKind,
}

// There isn't really an easy way to partially initialize a enum without troubles regarding data
// leaks via padding, so we have to resort to zero-initializing padding bytes manually
#[repr(u32)]
enum SavedFdKind {
    EventFd { count: u32, padding: u64 },
    Regular { cloned_fd: RawFd, position: u64 },
    Directory { cloned_fd: RawFd, position: u64 },
}

// Use the default value of sysctl vm.max_map_count
const MAX_MEMORY_MAPS: usize = 65530;

#[repr(C)]
struct MemoryMaps {
    orig_mem_fd: RawFd,
    count: usize,
    maps: [MemoryMap; MAX_MEMORY_MAPS],
}

#[repr(C)]
struct MemoryMap {
    base: usize,
    end: usize,
    prot: i32,
    flags: i32,
    fd: RawFd,
    offset: off_t,
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
    pub fn new(stdio_subst: File) -> Result<Self> {
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
        })
    }

    fn get_rdev(path: &str) -> Result<dev_t> {
        Ok(stat::stat(path)
            .with_context(|| format!("Failed to stat {path}"))?
            .st_rdev)
    }

    pub fn run(&self) -> Result<PreForkRun> {
        Ok(PreForkRun {
            manager: self,
            state: Cell::new(State::NotStarted),
        })
    }

    pub fn resume(
        &self,
        data: &mut SuspendData,
        stdio: [File; 3],
        cgroup: &mut cgroups::BoxCgroup,
    ) -> Result<tracing::TracedProcess> {
        log!("Resuming process");

        // 128 bytes ought to be enough for anyone
        // https://github.com/rust-lang/rust/issues/76915#issuecomment-1875845773
        #[repr(align(8))]
        struct AncillaryBuffer([u8; 128]);

        // Trigger clone
        let cwd = std::fs::File::open(&data.cwd).context("Failed to open cwd")?;
        let raw_fds = [
            stdio[0].as_raw_fd(),
            stdio[1].as_raw_fd(),
            stdio[2].as_raw_fd(),
            cwd.as_raw_fd(),
        ];
        let mut ancillary_buffer = AncillaryBuffer([0u8; 128]);
        let mut ancillary = SocketAncillary::new(&mut ancillary_buffer.0);
        assert!(ancillary.add_fds(&raw_fds));
        let control_data = [0];
        data.control_tx
            .send_vectored_with_ancillary(&[IoSlice::new(&control_data)], &mut ancillary)
            .context("Failed to send command to control socket")?;

        let wait_status = data.master.wait(system::WaitPidFlag::__WALL)?;
        match wait_status {
            system::WaitStatus::Stopped(..) => {
                // Only treat SIGSTOP as a success signal if it was sent explicitly, rather than
                // triggered by any sort of delayed mechanism
                let info = data.master.get_signal_info()?;
                if info.si_signo == libc::SIGSTOP && info.si_code == libc::SI_USER {
                    // Likely an error
                    let mut error = [0u8; 8];
                    data.master
                        .read_memory(data.inject_location + STEMCELL_STATE_OFFSET, &mut error)
                        .context("Failed to read-out error from stemcell")?;
                    let error = u64::from_ne_bytes(error);
                    return Err(recover_cxx_error(error, STEMCELL_CONTEXTS).context("In stemcell"));
                } else {
                    data.master.resume_signal(info.si_signo)?;
                    bail!("Master unexpectedly stopped with signal {}", info.si_signo);
                }
            }
            system::WaitStatus::PtraceEvent(_, _, libc::PTRACE_EVENT_CLONE) => {}
            _ => {
                data.master.detach()?;
                bail!("Unexpected status {wait_status:?} on master");
            }
        }

        let child_pid = Pid::from_raw(data.master.get_event_msg()? as pid_t);
        log!("Child spawned with pid {child_pid}");
        data.master.resume()?;

        let mut child = tracing::TracedProcess::new(child_pid)?;
        let wait_status = child.wait(system::WaitPidFlag::__WALL)?;
        ensure!(
            matches!(wait_status, system::WaitStatus::Stopped(_, libc::SIGSTOP)),
            "Expected SIGSTOP, got {wait_status:?}",
        );

        if child_pid != data.orig_pid {
            child.resume_signal(libc::SIGKILL)?;
            child.wait(system::WaitPidFlag::__WALL)?;

            loop {
                let wait_status = child.wait(system::WaitPidFlag::__WALL)?;
                match wait_status {
                    system::WaitStatus::Signaled(_, libc::SIGKILL) => break,
                    _ => bail!("Expected SIGKILL, got {wait_status:?}"),
                }
            }

            bail!("Pid {} has already been taken", data.orig_pid);
        }

        child.init().context("Failed to init child")?;
        child.resume().context("Failed to resume child")?;

        let had_sigstop = wait_for_raised_sigstop(&mut child, true)
            .context("Failed to wait for raise(SIGSTOP) in child")?;
        if had_sigstop {
            let mut error = [0u8; 8];
            child
                .read_memory(data.inject_location + STEMCELL_STATE_OFFSET, &mut error)
                .context("Failed to read-out error from child")?;
            let error = u64::from_ne_bytes(error);
            child.resume_signal(libc::SIGKILL)?;
            child.wait(system::WaitPidFlag::__WALL)?;
            return Err(recover_cxx_error(error, STEMCELL_CONTEXTS).context("In child"));
        }

        // Verify that the SIGSEGV was intentional
        let regs = child
            .get_registers()
            .context("Failed to get child registers")?;
        if regs.rsp != 0x5afec0def1e1d {
            child.resume_signal(libc::SIGKILL)?;
            child.wait(system::WaitPidFlag::__WALL)?;
            bail!("Child terminated with SIGSEGV");
        }

        // Only restore signal mask after the child unmaps itself, so that we don't handle signals
        // while it's mapped
        child
            .set_signal_mask(data.signal_mask)
            .context("Failed to restore signal mask")?;

        // Finally, restore CPU state
        child.set_registers(data.registers.clone());

        // I dare you
        child.resume().context("Failed to resume child")?;

        Ok(child)
    }
}

impl PreForkRun<'_> {
    fn suspend(&self, orig: &mut tracing::TracedProcess, options: SuspendOptions) -> Result<()> {
        self.state
            .set(State::Suspended(Suspender::new(orig, options).suspend()?));
        Ok(())
    }

    pub fn get_suspend_data(self) -> Result<SuspendData> {
        if let State::Suspended(data) = self.state.into_inner() {
            Ok(data)
        } else {
            bail!("Process has not been suspended")
        }
    }

    pub fn on_seccomp(&self, orig: &mut tracing::TracedProcess) -> Result<bool> {
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
                let fd = syscall_info.args[0] as RawFd;
                if (0..3).contains(&fd) {
                    self.suspend(orig, SuspendOptions::new_seccomp())?;
                    return Ok(true);
                }
            }
            libc::SYS_lseek => {
                let fd = syscall_info.args[0] as RawFd;
                let offset = syscall_info.args[1] as off_t;
                let whence = syscall_info.args[2] as i32;
                if (0..3).contains(&fd) {
                    // Disallow seeking to anywhere but the beginning
                    if offset != 0 || (whence != libc::SEEK_SET && whence != libc::SEEK_CUR) {
                        self.suspend(orig, SuspendOptions::new_seccomp())?;
                        return Ok(true);
                    }
                }
            }
            libc::SYS_mmap => {
                self.suspend(orig, SuspendOptions::new_seccomp())?;
                return Ok(true);
            }
            libc::SYS_dup2 | libc::SYS_dup3 => {
                let oldfd = syscall_info.args[0] as RawFd;
                let newfd = syscall_info.args[1] as RawFd;
                if (0..3).contains(&oldfd) || (0..3).contains(&newfd) {
                    self.suspend(orig, SuspendOptions::new_seccomp())?;
                    return Ok(true);
                }
            }
            libc::SYS_open | libc::SYS_openat => {
                // TOCTOU is not a problem as the user process is single-threaded
                self.state.set(State::WaitingOnOpen);
                orig.resume_syscall()?;
                return Ok(false);
            }
            libc::SYS_fcntl => {
                let fd = syscall_info.args[0] as RawFd;
                let cmd = syscall_info.args[1] as i32;
                if (0..3).contains(&fd)
                    && cmd != libc::F_GETFD
                    && cmd != libc::F_SETFD
                    && cmd != libc::F_GETFL
                {
                    self.suspend(orig, SuspendOptions::new_seccomp())?;
                    return Ok(true);
                }
            }
            libc::SYS_ioctl => {
                let fd = syscall_info.args[0] as RawFd;
                let request = syscall_info.args[1];
                if (0..3).contains(&fd) {
                    // These will return ENOTTY/ENOTSOCK anyway
                    if request != libc::TCGETS as u64 && request != libc::TIOCGPGRP as u64 {
                        self.suspend(orig, SuspendOptions::new_seccomp())?;
                        return Ok(true);
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
                        self.suspend(orig, SuspendOptions::new_seccomp())?;
                        return Ok(true);
                    }
                }
            }
            libc::SYS_getppid => {
                // TODO: this should probably return the real ppid
                // As if across PID namespace
                orig.set_syscall_result(0)?;
                orig.set_active_syscall_no(-1)?; // skip syscall
            }
            // TODO: pipe, sysinfo, modify_ldt, epoll*
            // TODO: move simple cases to seccomp filter for efficiency
            _ => {
                self.suspend(orig, SuspendOptions::new_seccomp())?;
                return Ok(true);
            }
        }

        orig.resume()?;
        Ok(false)
    }

    pub fn handle_syscall(&mut self, orig: &mut tracing::TracedProcess) -> Result<bool> {
        match self
            .should_suspend_after_syscall(orig)
            .context("Failed to check if should suspend after syscsall")?
        {
            Some(options) => {
                self.suspend(orig, options)
                    .context("Failed to suspend after syscall")?;
                Ok(true)
            }
            None => {
                orig.resume()?;
                Ok(false)
            }
        }
    }

    fn should_suspend_after_syscall(
        &mut self,
        orig: &mut tracing::TracedProcess,
    ) -> Result<Option<SuspendOptions>> {
        match self.state.get_mut() {
            State::WaitingOnOpen => {
                self.state.set(State::Alive);

                let fd = orig.get_syscall_result()? as RawFd;
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

            _ => bail!("PtraceSyscall on unexpected state"),
        }

        Ok(None)
    }
}

impl<'a> Suspender<'a> {
    pub fn new(orig: &'a mut tracing::TracedProcess, options: SuspendOptions) -> Self {
        Self {
            orig,
            options,
            inject_location: 0,
            master: None,
            transferred_fds: Vec::new(),
            forbidden_transferred_fds: HashSet::new(),
            stemcell_state: MaybeUninit::zeroed(),
            control_tx: None,
        }
    }

    pub fn suspend(mut self) -> Result<SuspendData> {
        // We would like to detach the restricted seccomp filter and attach the normal one.
        // Unfortunately, seccomp filters cannot be removed, so we have to cheat and create a new
        // process, effectively running fork() in userland.

        let started = Instant::now();
        log!("Suspend started on {started:?}");

        let syscall_info = self
            .orig
            .get_syscall_info()
            .context("Failed to get syscall info")?;
        let syscall_info = unsafe { syscall_info.u.seccomp };
        log!(
            "Suspending on {}",
            tracing::SyscallArgs {
                syscall_no: syscall_info.nr as i32,
                args: syscall_info.args.map(|arg| arg as usize)
            }
        );

        // Save register state
        let mut registers = self.orig.get_registers()?;
        // Jump back to the syscall instruction
        registers.rip -= self.orig.get_syscall_insn_length() as u64;
        // Change the -ENOSYS placed by seccomp to the real syscall number
        registers.rax = syscall_info.nr;

        // It's important to get the kernel messing with IP due to rseq out of the way as fast as
        // possible
        let rseq_info = self.save_rseq_info()?;

        // The working directory always exists because we don't allow deleting files before suspend
        let pid = self.orig.get_pid();
        let cwd = std::fs::read_link(format!("/proc/{pid}/cwd"))
            .with_context(|| format!("Failed to readlink /proc/{pid}/cwd"))?;

        let signal_mask = self
            .orig
            .get_signal_mask()
            .context("Failed to get signal mask")?;

        self.collect_file_descriptors()
            .context("Failed to collect file descriptors")?;
        self.collect_mm_options()
            .context("Failed to collect memory map options")?;

        let memory_maps = self.orig.get_memory_maps()?;
        self.translate_memory_maps(&memory_maps)
            .context("Failed to translate memory maps")?;

        // Find a location unused in the original process where we can safely map the parasite. We
        // will also use the same location for the stemcell in the master copy. Derive the requested
        // size from the size of the executable plus the stack, minding the red zone
        self.inject_location = self
            .find_inject_location(&memory_maps, PARASITE_MEMORY_SIZE)
            .context("Failed to find location for parasite")?;
        log!("Found free space at 0x{:x}", self.inject_location);

        self.infect_orig()
            .context("Failed to infect original process")?;
        self.collect_info_via_parasite()
            .context("Failed to collect information via parasite")?;

        self.create_controlling_socket()
            .context("Failed to create controlling socket")?;

        self.start_master().context("Failed to start master copy")?;

        self.restore_via_master()
            .context("Failed to restore via master")?;

        log!("Suspend finished in {:?}", started.elapsed());

        Ok(SuspendData {
            master: self.master.unwrap(),
            orig_pid: self.orig.get_pid(),
            inject_location: self.inject_location,
            cwd,
            control_tx: self.control_tx.unwrap(),
            registers,
            signal_mask,
        })
    }

    fn save_rseq_info(&self) -> Result<Option<RSeqInfo>> {
        // Check if IP is inside a restartable sequence. If it is, the kernel might jump to the
        // abort handler when we don't expect that to happen. Prevent this by resetting the
        // information about the critical section, if present.
        let rseq = self
            .orig
            .get_rseq_configuration()
            .context("Failed to get rseq configuration")?;
        if rseq.rseq_abi_size == 0 {
            return Ok(None);
        }
        let rseq_cs_ptr = rseq.rseq_abi_pointer as usize + std::mem::offset_of!(rseq_abi, rseq_cs);
        let rseq_cs = self
            .orig
            .read_word(rseq_cs_ptr)
            .context("Failed to read rseq CS pointer")?;
        if rseq_cs != 0 {
            self.orig
                .write_word(rseq_cs_ptr, 0)
                .context("Failed to override rseq CS pointer to 0")?;
        }
        Ok(Some(RSeqInfo {
            rseq_abi_pointer: rseq.rseq_abi_pointer as usize,
            rseq_abi_size: rseq.rseq_abi_size,
            flags: rseq.flags,
            signature: rseq.signature,
            rseq_cs,
        }))
    }

    fn find_inject_location(&self, maps: &[tracing::MemoryMap], size: usize) -> Result<usize> {
        let mmap_min_addr: usize = std::fs::read_to_string("/proc/sys/vm/mmap_min_addr")
            .context("Failed to read /proc/sys/vm/mmap_min_addr")?
            .trim()
            .parse()
            .context("Failed to parse /proc/sys/vm/mmap_min_addr")?;

        // Ban address 0, because perhaps that's a bit safer
        let mmap_min_addr = mmap_min_addr.max(4096);

        if mmap_min_addr + size <= maps[0].base {
            return Ok(mmap_min_addr);
        }
        for i in 1..maps.len() {
            if maps[i - 1].end + size <= maps[i].base {
                return Ok(maps[i - 1].end);
            }
        }
        Ok(maps.last().unwrap().end)
    }

    fn infect_orig(&mut self) -> Result<()> {
        log!("Infecting original process");

        // mmap an rwx segment
        self.orig
            .exec_syscall(
                syscall!(mmap(
                    self.inject_location,
                    PARASITE_MEMORY_SIZE,
                    PROT_READ | PROT_WRITE | PROT_EXEC,
                    MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED,
                    -1,
                    0
                )),
                self.options.inside_syscall,
            )
            .context("Failed to mmap parasite segment")?;

        // Load code
        self.orig
            .write_memory(self.inject_location, PARASITE)
            .context("Failed to write parasite segment")?;

        // Reset processor stack (direction flag, x87 state, etc.). This should prevent the original
        // process from configuring the CPU in a way the parasite doesn't expect
        let mut regs: tracing::Registers = unsafe { std::mem::zeroed() };
        // Call _start() with a valid stack
        regs.rip = self.inject_location as u64;
        // Put stack pointer to incorrect value to not fuck up user memory
        regs.rsp = 0xdeadbeef00000000 as u64;
        // This relies on the fact that segment registers point at GDT, which is shared between all
        // processes
        unsafe {
            // This could be a single instruction rather than mov to a general register followed by
            // a mov to memory (which Rust doesn't easily enable), but that's a premature
            // optimization
            std::arch::asm!("mov {}, cs", out(reg) regs.cs);
            std::arch::asm!("mov {}, ss", out(reg) regs.ss);
            std::arch::asm!("mov {}, ds", out(reg) regs.ds);
            std::arch::asm!("mov {}, es", out(reg) regs.es);
            std::arch::asm!("mov {}, fs", out(reg) regs.fs);
            std::arch::asm!("mov {}, gs", out(reg) regs.gs);
        }
        self.orig.set_registers(regs);

        Ok(())
    }

    fn collect_info_via_parasite(&mut self) -> Result<()> {
        log!("Running parasite in original process");

        // We want the parasite to execute some syscalls in the original process. Unfortunately,
        // these syscalls include ones blocked by seccomp due to the nature of prefork, so we have
        // to explicitly allow them via ptrace.

        self.orig.init()?;
        self.orig.resume()?;

        wait_for_raised_sigstop(&mut self.orig, false)
            .context("Failed to wait for raise(SIGSTOP) in parasite")?;

        // Don't detach until after delivering SIGSTOP as to not corrupt memory
        self.orig
            .resume_signal(libc::SIGSTOP)
            .context("Failed to send SIGSTOP to parasite")?;
        self.orig
            .detach()
            .context("Failed to detach from parasite")?;

        let mut parasite_state = MaybeUninit::<ParasiteState>::zeroed();
        self.orig
            .read_memory(self.inject_location + PARASITE_STATE_OFFSET, unsafe {
                MaybeUninit::slice_assume_init_mut(parasite_state.as_bytes_mut())
            })
            .context("Failed to read-out state from parasite")?;
        let parasite_state = unsafe { parasite_state.assume_init_ref() };

        if parasite_state.result != 0 {
            return Err(
                recover_cxx_error(parasite_state.result, PARASITE_CONTEXTS).context("In parasite")
            );
        }

        // Perform a bitwise copy as opposed to copy that might leak data in padding bytes
        let stemcell_state_mut = unsafe { self.stemcell_state.assume_init_mut() };
        unsafe {
            std::ptr::copy_nonoverlapping(
                &parasite_state.alternative_stack,
                &mut stemcell_state_mut.alternative_stack,
                1,
            );
            std::ptr::copy_nonoverlapping(
                &parasite_state.arch_prctl_options,
                &mut stemcell_state_mut.arch_prctl_options,
                1,
            );
            std::ptr::copy_nonoverlapping(
                &parasite_state.itimers,
                &mut stemcell_state_mut.itimers,
                1,
            );
            std::ptr::copy_nonoverlapping(
                &parasite_state.signal_handlers,
                &mut stemcell_state_mut.signal_handlers,
                1,
            );
            stemcell_state_mut.mm_options.brk = parasite_state.program_break;
            stemcell_state_mut.personality = parasite_state.personality;
            stemcell_state_mut.thp_options = parasite_state.thp_options;
            stemcell_state_mut.tid_address = parasite_state.tid_address;
            stemcell_state_mut.umask = parasite_state.umask;
        }

        Ok(())
    }

    fn collect_file_descriptors(&mut self) -> Result<()> {
        let file_descriptors =
            &mut unsafe { self.stemcell_state.assume_init_mut() }.file_descriptors;

        let pid = self.orig.get_pid();

        for fd_entry in std::fs::read_dir(format!("/proc/{pid}/fd"))
            .with_context(|| format!("Failed to read /proc/{pid}/fd"))?
        {
            let fd_entry = fd_entry.with_context(|| format!("Failed to read /proc/{pid}/fd"))?;
            let fd: RawFd = fd_entry
                .file_name()
                .into_string()
                .map_err(|_| anyhow!("Invalid file name in /proc/{pid}/fd"))?
                .parse()
                .with_context(|| format!("Invalid file name in /proc/{pid}/fd"))?;
            if fd < 3 {
                continue;
            }

            let mut pos: Option<u64> = None;
            let mut flags: Option<i32> = None;
            let mut eventfd_count = None;

            let fdinfo_path = format!("/proc/{pid}/fdinfo/{fd}");
            let fdinfo = File::open(&fdinfo_path)
                .with_context(|| format!("Failed to open {fdinfo_path}"))?;
            let fdinfo_reader = BufReader::new(fdinfo);
            for line in fdinfo_reader.lines() {
                let line = line.with_context(|| format!("Failed to read {fdinfo_path}"))?;
                let Some((key, value)) = line.split_once(':') else {
                    continue;
                };
                let value = value.trim();
                match key {
                    "pos" => {
                        pos = Some(value.parse().context("'pos' is not a number")?);
                    }
                    "flags" => {
                        flags = Some(
                            i32::from_str_radix(value, 16)
                                .context("'flags' is not a hexadecimal number")?,
                        );
                    }
                    "eventfd-count" => {
                        eventfd_count =
                            Some(value.parse().context("'eventfd-count' is not a number")?);
                    }
                    _ => {}
                }
            }

            let flags = flags.context("'flags' missing")?;

            let saved_fd = file_descriptors
                .fds
                .get_mut(file_descriptors.count)
                .context("Too many file descriptors")?;
            file_descriptors.count += 1;

            saved_fd.flags = flags;
            saved_fd.fd = fd;

            if let Some(count) = eventfd_count {
                saved_fd.kind = SavedFdKind::EventFd { count, padding: 0 };
                continue;
            }

            let position = pos.context("'pos' missing on regular/directory fd")?;

            let file = unsafe {
                OwnedFd::from_raw_fd(fcntl::open(
                    &fd_entry.path(),
                    fcntl::OFlag::from_bits_retain(flags & !(libc::O_CREAT | libc::O_TMPFILE)),
                    stat::Mode::empty(),
                )?)
            };
            let stat = stat::fstat(file.as_raw_fd()).context("Failed to stat file")?;
            let cloned_fd = self.transferred_fds.len() as RawFd;
            self.transferred_fds.push(file);
            self.forbidden_transferred_fds.insert(fd);

            saved_fd.kind = if stat.st_mode & libc::S_IFMT == libc::S_IFDIR {
                SavedFdKind::Directory {
                    cloned_fd,
                    position,
                }
            } else {
                SavedFdKind::Regular {
                    cloned_fd,
                    position,
                }
            };
        }

        Ok(())
    }

    fn collect_mm_options(&mut self) -> Result<()> {
        let stat = self
            .orig
            .get_stat()
            .context("Failed to get stat of original process")?;
        let mm_options = &mut unsafe { self.stemcell_state.assume_init_mut() }.mm_options;
        mm_options.start_code = stat.start_code;
        mm_options.end_code = stat.end_code;
        mm_options.start_data = stat.start_data;
        mm_options.end_data = stat.end_data;
        mm_options.start_brk = stat.start_brk;
        // brk is filled by parasite
        mm_options.start_stack = stat.start_stack;
        mm_options.arg_start = stat.arg_start;
        mm_options.arg_end = stat.arg_end;
        mm_options.env_start = stat.env_start;
        mm_options.env_end = stat.env_end;
        mm_options.auxv = 0;
        mm_options.auxv_size = 0;
        mm_options.exe_fd = -1;
        Ok(())
    }

    fn translate_memory_maps(&mut self, memory_maps: &[tracing::MemoryMap]) -> Result<()> {
        let translated_maps_mut = &mut unsafe { self.stemcell_state.assume_init_mut() }.memory_maps;

        translated_maps_mut.orig_mem_fd = self.transferred_fds.len() as RawFd;
        self.transferred_fds.push(
            self.orig
                .get_mem()
                .try_clone()
                .context("Failed to clone /proc/.../mem of original process")?
                .into(),
        );

        let mut file_indices = HashMap::new();

        for map in memory_maps {
            // This segment has the same address in all processes
            if map.desc == "[vsyscall]" {
                continue;
            }
            // This segment is mapped as a part of ARCH_MAP_VDSO_64
            if map.desc == "[vdso]" {
                continue;
            }

            let alloced = translated_maps_mut
                .maps
                .get_mut(translated_maps_mut.count)
                .context("Too many memory mappings")?;
            translated_maps_mut.count += 1;

            alloced.base = map.base;
            alloced.end = map.end;

            // [vvar] and [vdso] are handled manually
            // FIXME: one could theoretically unmap a part of [vvar]/[vdso], which we don't
            // replicate correctly
            if map.desc == "[vvar]" {
                alloced.prot = -1;
                alloced.fd = -1;
                continue;
            }

            alloced.prot = map.prot;
            alloced.flags = libc::MAP_FIXED_NOREPLACE;
            alloced.offset = map.offset;

            if map.shared {
                // Shared memory is either backed by a read-only file or /dev/zero (anonymous
                // mappings are backed by the latter). Therefore, we can mmap (and populate)
                // read-only files before fork, and /dev/zero after fork.

                // One problem is that two virtual addresses can be mmapped to the same physical
                // address, e.g. if we do memfd_create() and then mmap() it at two addresses.
                // Luckily, we have disabled memfd_create() in prefork mode, so that doesn't bother
                // us.

                alloced.flags |= libc::MAP_SHARED;
            } else {
                alloced.flags |= libc::MAP_PRIVATE;
            }

            if map.desc == "[stack]" {
                // FIXME: This assumes that a) only [stack] uses MAP_GROWSDOWN, b) no one has
                // disabled MAP_GROWSDOWN on [stack]. This is the case for most runtimes, but is
                // horrendously broken. We should parse /proc/<pid>/smaps instead. The same applies
                // to MAP_STACK. Also, they say that MAP_GROWSDOWN'ing a new page is not quite the
                // same thing as what the kernel does when allocating the main stack, so we should
                // figure that out.
                alloced.flags |= libc::MAP_GROWSDOWN | libc::MAP_STACK;
            }

            if map.inode == 0 {
                alloced.flags |= libc::MAP_ANONYMOUS;
                alloced.fd = -1;
                continue;
            }

            // Cache file descriptors (actually, indices -- they are resolved to fds later) to the
            // same file
            let key = (map.major, map.minor, map.inode);
            if let Some(index) = file_indices.get(&key) {
                alloced.fd = *index;
                continue;
            }

            // I'm not proud of this workaround. We can't open /proc/.../map_files/... because that
            // requires capabilities in the root userns, which we don't have. Instead, we abuse the
            // fact that the file system is immutable during prefork, and thus the path reported by
            // readlink (as opposed to /proc/.../maps, which may corrupt special characters) is
            // always valid. Moreover, we know that the file was opened with O_RDONLY (save for
            // /dev/zero, but that's an exception for which O_RDONLY works just as well), and thus
            // we can do the same here
            match self.orig.get_memory_mapped_file_path(&map)? {
                Some(file_path) => {
                    if file_path == Path::new("/dev/zero") {
                        alloced.prot |= -0x80000000;
                    }
                    let file = File::open(&file_path)
                        .with_context(|| {
                            format!(
                                "Failed to open {file_path:?}, mapped to {:x}-{:x}",
                                map.base, map.end,
                            )
                        })?
                        .into();
                    alloced.fd = self.transferred_fds.len() as RawFd;
                    file_indices.insert(key, alloced.fd);
                    self.transferred_fds.push(file);
                }
                None => {
                    // Anonymous mapping
                    alloced.flags |= libc::MAP_ANONYMOUS;
                    alloced.fd = -1;
                }
            }
        }

        Ok(())
    }

    fn create_controlling_socket(&mut self) -> Result<()> {
        log!("Creating controller socket");

        let (tx, rx) = unsafe {
            let mut fds = [0, 0];
            if libc::socketpair(
                libc::AF_UNIX,
                libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
                0,
                fds.as_mut_ptr(),
            ) == -1
            {
                return Err(std::io::Error::last_os_error())
                    .context("Failed to create socket pair");
            }
            (
                UnixStream::from_raw_fd(fds[0]),
                OwnedFd::from_raw_fd(fds[1]),
            )
        };

        let stemcell_state = unsafe { self.stemcell_state.assume_init_mut() };

        stemcell_state.controlling_fd = self.transferred_fds.len() as i32;
        self.transferred_fds.push(rx);

        self.control_tx = Some(tx);

        Ok(())
    }

    fn start_master(&mut self) -> Result<()> {
        log!("Starting master copy");

        let (theirs, mut ours) = crossmist::channel().context("Failed to create a pipe")?;
        let (transferred_fds_tx, mut transferred_fds_rx) =
            crossmist::channel().context("Failed to create a pipe")?;
        let master_process = prefork_master
            .spawn(
                theirs,
                self.inject_location,
                std::mem::take(&mut self.transferred_fds),
                std::mem::take(&mut self.forbidden_transferred_fds),
                transferred_fds_tx,
            )
            .context("Failed to spawn the child")?;
        let master_pid = Pid::from_raw(master_process.id());

        let transferred_fds = transferred_fds_rx
            .recv()
            .context("Failed to receive transferred fds from master copy")?
            .context("Master didn't deliver any transferred fds")?;
        self.patch_transferred_fds(&transferred_fds)
            .context("Failed to to patch transferred fds")?;

        // The child will either exit or trigger SIGTRAP on execve() to stemcell due to ptrace
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
                bail!("waitpid returned unexpected status at stemcell: {wait_status:?}");
            }
        }

        let master = tracing::TracedProcess::new(master_pid)?;
        master.init().context("Failed to init master")?;
        self.master = Some(master);

        Ok(())
    }

    fn patch_transferred_fds(&mut self, fds: &[RawFd]) -> Result<()> {
        log!("Patching transferred fds");

        let state = unsafe { self.stemcell_state.assume_init_mut() };

        state.memory_maps.orig_mem_fd = fds[state.memory_maps.orig_mem_fd as usize];
        for map in &mut state.memory_maps.maps[..state.memory_maps.count] {
            if map.fd != -1 {
                map.fd = fds[map.fd as usize];
            }
        }

        for fd in &mut state.file_descriptors.fds[..state.file_descriptors.count] {
            match fd.kind {
                SavedFdKind::EventFd { .. } => {}
                SavedFdKind::Regular {
                    cloned_fd,
                    position,
                } => {
                    fd.kind = SavedFdKind::Regular {
                        cloned_fd: fds[cloned_fd as usize],
                        position,
                    }
                }
                SavedFdKind::Directory {
                    cloned_fd,
                    position,
                } => {
                    fd.kind = SavedFdKind::Directory {
                        cloned_fd: fds[cloned_fd as usize],
                        position,
                    }
                }
            }
        }

        state.controlling_fd = fds[state.controlling_fd as usize];

        Ok(())
    }

    fn restore_via_master(&mut self) -> Result<()> {
        log!("Uploading data to master");

        let master = self.master.as_mut().unwrap();

        master
            .write_memory(self.inject_location + STEMCELL_STATE_OFFSET, unsafe {
                MaybeUninit::slice_assume_init_ref(self.stemcell_state.as_bytes())
            })
            .context("Failed to write state to master")?;

        log!("Resuming stemcell");
        master.resume().context("Failed to resume stemcell")?;

        wait_for_raised_sigstop(master, false)
            .context("Failed to wait for raise(SIGSTOP) in stemcell")?;

        let mut stemcell_result = [0u8; 8];
        master
            .read_memory(
                self.inject_location + STEMCELL_STATE_OFFSET,
                &mut stemcell_result,
            )
            .context("Failed to read-out result from stemcell")?;
        let stemcell_result = u64::from_ne_bytes(stemcell_result);

        if stemcell_result != 0 {
            master.detach()?;
            return Err(
                recover_cxx_error(stemcell_result, STEMCELL_CONTEXTS).context("In stemcell")
            );
        }

        log!("Entering fork loop");
        master
            .resume_signal(libc::SIGCONT)
            .context("Failed to resume stemcell with SIGCONT")?;

        Ok(())
    }
}

fn recover_cxx_error(mut error: u64, context_map: &[&'static str]) -> anyhow::Error {
    let mut contexts = Vec::new();
    while error >= 0x10000 {
        let context = (error & 0xff) as usize;
        error >>= 8;
        if context >= context_map.len() {
            log!(
                impossible,
                "C++ code returned an error that could not successfully be decoded. This \
                 indicates the process has reached user code. This should not cause any \
                 vulnerabilities per se, but is a highly unexpected event that might trigger \
                 corner cases or indicate prefork support is lacking."
            );
            return anyhow!("C++ error has invalid context ID");
        }
        contexts.push(context_map[context]);
    }
    let mut error = if error == 0x8000 {
        anyhow!("Generic error")
    } else {
        let errno = (error as u16).wrapping_neg() as i32;
        anyhow!("Syscall error {}", string_table::errno_to_name(errno))
    };
    for &context in contexts.iter().rev() {
        error = error.context(context);
    }
    error
}

fn wait_for_raised_sigstop(
    process: &mut tracing::TracedProcess,
    allow_sigsegv: bool,
) -> Result<bool> {
    // We must consider that in the original process, at any point in time, a signal may arrive,
    // delayed from the user's code. The only signal we want to handle in a special way is SIGSTOP,
    // which the parasite sends when it successfully captures the state and the stemcell sends when
    // it successfully restores the state.
    loop {
        let wait_status = process.wait(system::WaitPidFlag::__WALL)?;
        // If we don't detach from the process, it won't be able to receive SIGKILL and
        // terminate. So do that, even though that technically allows the process to do weird
        // stuff in the meantime.
        match wait_status {
            system::WaitStatus::Exited(_, code) => {
                bail!("Process unexpectedly exited with code {code}");
            }
            system::WaitStatus::Signaled(_, signal) => {
                bail!("Process unexpectedly killed with signal {signal}");
            }
            system::WaitStatus::Stopped(..) => {
                // Only treat SIGSTOP as a success signal if it was sent explicitly, rather than
                // triggered by any sort of delayed mechanism
                let info = process.get_signal_info()?;
                if info.si_signo == libc::SIGSTOP && info.si_code == libc::SI_USER {
                    return Ok(true);
                } else if info.si_signo == libc::SIGSEGV && allow_sigsegv {
                    log!(
                        "SIGSEGV at address {:?}; this might be expected, only worry about this \
                         if an error appears later",
                        unsafe { info.si_addr() },
                    );
                    return Ok(false);
                } else {
                    process.resume_signal(libc::SIGKILL)?;
                    process.wait(system::WaitPidFlag::__WALL)?;
                    // For ease of debugging
                    let signal_name = match info.si_signo {
                        libc::SIGILL => Some("SIGILL"),
                        libc::SIGSEGV => Some("SIGSEGV"),
                        libc::SIGBUS => Some("SIGBUS"),
                        _ => None,
                    };
                    if let Some(name) = signal_name {
                        bail!("Unexpected {name} at address {:?}", unsafe {
                            info.si_addr()
                        });
                    } else {
                        bail!("Unexpected stop with signal {}", info.si_signo);
                    }
                }
            }
            system::WaitStatus::PtraceEvent(..) => process.resume()?,
            _ => {
                process.detach()?;
                bail!("Unexpected status");
            }
        }
    }
}

#[crossmist::func]
fn prefork_master(
    mut pipe: crossmist::Sender<String>,
    inject_location: usize,
    mut transferred_fds: Vec<OwnedFd>,
    forbidden_transferred_fds: HashSet<RawFd>,
    mut transferred_fds_tx: Sender<Vec<RawFd>>,
) {
    let result: Result<()> = try {
        // Make sure transferred fds are not forbidden and make them all non-CLOEXEC
        let mut target_fd = 3;
        for fd in &mut transferred_fds {
            if !forbidden_transferred_fds.contains(&fd.as_raw_fd()) {
                // Easy case
                fcntl::fcntl(
                    fd.as_raw_fd(),
                    fcntl::FcntlArg::F_SETFD(fcntl::FdFlag::empty()),
                )
                .context("Failed to make transferred fd non-CLOEXEC")?;
                continue;
            }
            // Without closing the current fd, open a new one at an allowed location
            while forbidden_transferred_fds.contains(&target_fd)
                || fcntl::fcntl(target_fd, fcntl::FcntlArg::F_GETFD).is_ok()
            {
                target_fd += 1;
            }
            *fd = unsafe {
                OwnedFd::from_raw_fd(
                    unistd::dup2(fd.as_raw_fd(), target_fd)
                        .context("Failed to clone transferred fd")?,
                )
            };
            target_fd += 1;
        }
        transferred_fds_tx
            .send(&transferred_fds.iter().map(AsRawFd::as_raw_fd).collect())
            .context("Failed to send transferred fds to manager")?;

        // We don't want to bother about emulating setsid() in userspace fork, so use it by default
        unistd::setsid().context("Failed to setsid")?;

        // memfd should be created before applying seccomp filter
        // Patch the ELF header to use the right inject location. Yes, this is effectively
        // relocations reinvented
        let mut stemcell_elf = Vec::from(STEMCELL);
        for &offset in STEMCELL_RELOCATIONS {
            let chunk = stemcell_elf[offset..].first_chunk_mut().unwrap();
            *chunk = (usize::from_ne_bytes(*chunk) - 0xdeadbeef000 + inject_location).to_ne_bytes();
        }

        let stemcell = system::make_memfd("stemcell", &stemcell_elf)?;

        // This mostly repeats the code in running::executor_worker
        timens::disable_native_instructions()
            .context("Failed to disable native timens instructions")?;
        prctl::set_no_new_privs().context("Failed to set no_new_privs")?;
        // FIXME: we should stop the user from interactive with the master copy
        userns::drop_privileges().context("Failed to drop privileges")?;
        // FIXME: chdir, stdio

        ptrace::traceme().context("Failed to ptrace(PTRACE_TRACEME)")?;
        tracing::apply_seccomp_filter(false).context("Failed to apply seccomp filter")?;
        unistd::fexecve::<&CStr, &CStr>(
            stemcell.as_raw_fd(),
            &[CStr::from_bytes_with_nul(b"stemcell\0").unwrap()],
            &[],
        )
        .context("execv failed")?;
    };

    if let Err(e) = result {
        pipe.send(&format!("{e:?}"))
            .expect("Failed to report error to parent");
    }
}
