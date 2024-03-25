use crate::{
    copy_field_by_field,
    linux::{cgroups, ids, running, string_table, system, timens, tracing, tracing::Timer, userns},
    log, syscall,
    zeroed_padding::ZeroedPadding,
};
use anyhow::{anyhow, bail, ensure, Context, Result};
use crossmist::{Object, Sender};
use nix::{
    fcntl, libc,
    libc::{dev_t, mode_t, off_t, pid_t, siginfo_t},
    sys::{signal, stat, wait},
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
    rlimits: [libc::rlimit; 16],
}

// ZeroedPadding is used to avoid data leaks via padding
pub struct Suspender<'a> {
    orig: &'a mut tracing::TracedProcess,
    hard_rlimits: [libc::rlim_t; 16],
    orig_cgroup: &'a cgroups::BoxCgroup,
    options: SuspendOptions,
    inject_location: usize,
    master: Option<tracing::TracedProcess>,
    transferred_fds: Vec<OwnedFd>,
    forbidden_transferred_fds: HashSet<RawFd>,
    stemcell_state: ZeroedPadding<StemcellState>,
    control_tx: Option<UnixStream>,
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
const STEMCELL_SIZE: usize = include!("../../target/stemcell.size");
const STEMCELL_CONTEXTS: &[&str] = &include!("../../target/stemcell.result_context_map.json");
const STEMCELL_RELOCATIONS: &[usize] = &include!("../../target/stemcell.relocations");
const STEMCELL_STATE_OFFSET: usize = include!("../../target/stemcell.state");
const STEMCELL_MEMORY_SIZE: usize = (STEMCELL_SIZE + 4095) / 4096 * 4096;

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

#[cfg(target_arch = "x86_64")]
#[repr(C)]
struct ArchPrctlOptions {
    fs_base: usize,
    gs_base: usize,
    cpuid_status: usize,
}

#[cfg(not(target_arch = "x86_64"))]
struct ArchPrctlOptions;

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
struct RobustList {
    head: usize,
    len: usize,
}

#[repr(C)]
struct ParasiteState {
    result: u64,
    alternative_stack: libc::stack_t,
    arch_prctl_options: ArchPrctlOptions,
    itimers: ItimersState,
    program_break: usize,
    personality: usize,
    robust_list: RobustList,
    signal_handlers: [kernel_sigaction; 64],
    thp_options: usize,
    tid_address: usize,
    umask: libc::mode_t,
}

#[repr(C)]
struct TimerList {
    timers: [Timer; 64],
    timer_count: usize,
}

#[repr(C)]
struct StemcellState {
    result: u64,
    end_of_memory_space: usize,
    alternative_stack: libc::stack_t,
    arch_prctl_options: ArchPrctlOptions,
    file_descriptors: FileDescriptors,
    itimers: ItimersState,
    memory_maps: MemoryMaps,
    mm_options: prctl_mm_map,
    pending_signals: PendingSignals,
    personality: usize,
    robust_list: RobustList,
    rseq: Rseq,
    signal_handlers: [kernel_sigaction; 64],
    thp_options: usize,
    tid_address: usize,
    timers: TimerList,
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
    // EventFd is read in C code
    #[allow(unused)]
    EventFd {
        count: u32,
        padding: u64,
    },
    Regular {
        cloned_fd: RawFd,
        position: u64,
    },
    Directory {
        cloned_fd: RawFd,
        position: u64,
    },
}

// Use the default value of sysctl vm.max_map_count
const MAX_MEMORY_MAPS: usize = 65530;

#[repr(C)]
struct MemoryMaps {
    orig_mem_fd: RawFd,
    orig_pagemap_fd: RawFd,
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

#[repr(C)]
struct Rseq {
    rseq: usize,
    rseq_len: u32,
    flags: i32,
    sig: u32,
}

pub const MAX_PENDING_SIGNALS: usize = 1024;

#[repr(C)]
struct PendingSignals {
    count_per_thread: usize,
    count_per_process: usize,
    pending_per_thread: [libc::siginfo_t; MAX_PENDING_SIGNALS],
    pending_per_process: [libc::siginfo_t; MAX_PENDING_SIGNALS],
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

        let wait_status = data.master.wait()?;
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
                    bail_signal(info).context("Master is acting weird")?;
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
        let wait_status = child.wait()?;
        ensure!(
            matches!(wait_status, system::WaitStatus::Stopped(_, libc::SIGSTOP)),
            "Expected SIGSTOP, got {wait_status:?}",
        );

        if child_pid != data.orig_pid {
            child.resume_signal(libc::SIGKILL)?;
            wait_for_sigkill(&mut child)?;
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
            wait_for_sigkill(&mut child)?;
            return Err(recover_cxx_error(error, STEMCELL_CONTEXTS).context("In child"));
        }

        // Verify that the SIGSEGV was intentional
        let regs = child
            .registers_ref()
            .context("Failed to get child registers")?;
        if regs.get_stack_pointer() != 0x5afec0def1e1d {
            child.resume_signal(libc::SIGKILL)?;
            wait_for_sigkill(&mut child)?;
            bail!("Child terminated with SIGSEGV");
        }

        // Only restore signal mask after the child unmaps itself, so that we don't handle signals
        // while it's mapped
        child
            .set_signal_mask(data.signal_mask)
            .context("Failed to restore signal mask")?;

        // Only restore rlimits just before running the child in user code, so that the limits don't
        // bring down the stemcell
        for (i, rlimit) in data.rlimits.iter().enumerate() {
            child
                .set_rlimit(i as i32, *rlimit)
                .context("Failed to restore rlimit")?;
        }

        // Finally, restore CPU state
        child.set_registers(data.registers.clone());

        // And restrict the process
        cgroup
            .add_process(child_pid.as_raw())
            .context("Failed to move process to cgroup")?;

        // I dare you
        child.resume().context("Failed to resume child")?;

        log!("Restore complete");

        Ok(child)
    }
}

impl PreForkRun<'_> {
    fn suspend(
        &self,
        orig: &mut running::ProcessInfo,
        orig_cgroup: &cgroups::BoxCgroup,
        options: SuspendOptions,
    ) -> Result<()> {
        self.state.set(State::Suspended(
            Suspender::new(
                &mut orig.traced_process,
                orig.prefork_hard_rlimits.unwrap(),
                orig_cgroup,
                options,
            )
            .suspend()?,
        ));
        Ok(())
    }

    pub fn get_suspend_data(self) -> Result<SuspendData> {
        if let State::Suspended(data) = self.state.into_inner() {
            Ok(data)
        } else {
            bail!("Process has not been suspended")
        }
    }

    pub fn abort(self) -> Result<()> {
        let State::Suspended(SuspendData { mut master, .. }) = self.state.into_inner() else {
            return Ok(());
        };
        signal::kill(master.get_pid(), signal::Signal::SIGKILL)
            .context("Failed to SIGKILL master")?;
        wait_for_sigkill(&mut master).context("Failed to wait for SIGKILL on master")
    }

    pub fn on_seccomp(
        &self,
        orig: &mut running::ProcessInfo,
        syscall_info: tracing::ptrace_syscall_info_seccomp,
        box_cgroup: &cgroups::BoxCgroup,
    ) -> Result<bool> {
        // Allow all operations we can checkpoint-restore that don't touch the filesystem in an
        // impure way, e.g. open an fd to a file that can later be written to or to the standard
        // stream that might later be redirected somewhere else

        match syscall_info.nr as i64 {
            // TOCTOU is not a problem as the user process is single-threaded
            // XXX This WILL break on non-(x86_64|aarch64) architectures!
            #[cfg(target_arch = "x86_64")]
            libc::SYS_open | libc::SYS_openat => {
                self.state.set(State::WaitingOnOpen);
                orig.traced_process.resume_syscall()?;
                Ok(false)
            }
            #[cfg(target_arch = "aarch64")]
            libc::SYS_openat => {
                self.state.set(State::WaitingOnOpen);
                orig.traced_process.resume_syscall()?;
                Ok(false)
            }
            _ => {
                // If the seccomp filter returns TRACE for any other syscall, it has decided that
                // a suspend is necessary.
                self.suspend(orig, box_cgroup, SuspendOptions::new_seccomp())
                    .context("Failed to suspend on seccomp")?;
                Ok(true)
            }
        }
    }

    pub fn handle_syscall(
        &mut self,
        orig: &mut running::ProcessInfo,
        box_cgroup: &cgroups::BoxCgroup,
    ) -> Result<bool> {
        match self
            .should_suspend_after_syscall(&mut orig.traced_process)
            .context("Failed to check if should suspend after syscsall")?
        {
            Some(options) => {
                self.suspend(orig, box_cgroup, options)
                    .context("Failed to suspend after syscall")?;
                Ok(true)
            }
            None => {
                orig.traced_process.resume()?;
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

                let fd = orig.registers_ref()?.get_syscall_result() as RawFd;
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
                    log!("Suspending on writable file");
                    return Ok(Some(SuspendOptions::new_after_open(fd)));
                }
            }

            _ => bail!("PtraceSyscall on unexpected state"),
        }

        Ok(None)
    }
}

impl<'a> Suspender<'a> {
    pub fn new(
        orig: &'a mut tracing::TracedProcess,
        hard_rlimits: [libc::rlim_t; 16],
        orig_cgroup: &'a cgroups::BoxCgroup,
        options: SuspendOptions,
    ) -> Self {
        Self {
            orig,
            hard_rlimits,
            orig_cgroup,
            options,
            inject_location: 0,
            master: None,
            transferred_fds: Vec::new(),
            forbidden_transferred_fds: HashSet::new(),
            stemcell_state: unsafe { ZeroedPadding::zeroed() },
            control_tx: None,
        }
    }

    pub fn suspend(mut self) -> Result<SuspendData> {
        // We would like to detach the restricted seccomp filter and attach the normal one.
        // Unfortunately, seccomp filters cannot be removed, so we have to cheat and create a new
        // process, effectively running fork() in userland.

        let started = Instant::now();
        log!("Suspend started on {started:?}");

        // Save register state
        let registers = self.orig.registers_mut().context("Get orig registers")?;
        // Jump back to the syscall instruction
        registers.set_instruction_pointer(
            registers.get_instruction_pointer() - tracing::TracedProcess::get_syscall_insn_length(),
        );
        // The rest of the changes shouldn't happen in the process
        let mut registers = registers.clone();
        // Change the -ENOSYS placed by seccomp to the real syscall number
        registers.set_syscall_no(registers.get_active_syscall_no());

        // It's important to get the kernel messing with IP due to rseq out of the way as fast as
        // possible
        self.collect_rseq(&mut registers)
            .context("Failed to handle rseq")?;

        // The working directory always exists because we don't allow deleting files before suspend
        let pid = self.orig.get_pid();
        let cwd = std::fs::read_link(format!("/proc/{pid}/cwd"))
            .with_context(|| format!("Failed to readlink /proc/{pid}/cwd"))?;

        let signal_mask = self
            .orig
            .get_signal_mask()
            .context("Failed to get signal mask")?;
        // Make sure no asynchronous signal can affect the parasite
        self.orig
            .set_signal_mask(!0)
            .context("Failed to block all signals")?;

        self.collect_pending_signals()
            .context("Failed to collect pending signals")?;
        self.collect_file_descriptors()
            .context("Failed to collect file descriptors")?;
        self.collect_mm_options()
            .context("Failed to collect memory map options")?;
        self.collect_timers().context("Failed to collect timers")?;

        let memory_maps = self.orig.get_memory_maps().context("Get memory maps")?;
        self.translate_memory_maps(&memory_maps)
            .context("Failed to translate memory maps")?;

        let rlimits = self
            .collect_rlimits()
            .context("Failed to collect orig rlimits")?;

        self.unchain_orig()
            .context("Failed to unchain original process")?;
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
            rlimits,
        })
    }

    fn collect_rseq(&mut self, cloned_registers: &mut tracing::Registers) -> Result<()> {
        let rseq = self
            .orig
            .get_rseq_configuration()
            .context("Failed to get rseq configuration")?;

        copy_field_by_field!(
            self.stemcell_state.rseq,
            {
                rseq: rseq.rseq_abi_pointer as usize,
                rseq_len: rseq.rseq_abi_size,
                flags: rseq.flags as i32,
                sig: rseq.signature,
            }
        );

        if rseq.rseq_abi_pointer == 0 {
            // If the user process doesn't use rseq at all, we don't need to handle anything
            return Ok(());
        }

        let rseq_cs_ptr_ptr =
            rseq.rseq_abi_pointer as usize + std::mem::offset_of!(rseq_abi, rseq_cs);
        let rseq_cs_ptr = self
            .orig
            .read_word(rseq_cs_ptr_ptr)
            .context("Failed to read rseq CS pointer")?;

        if rseq_cs_ptr == 0 {
            // If we are outside the critical section, we don't need to handle anything
            return Ok(());
        }

        // Either we are in a critical section and need to get out of it (as if preempted) and reset
        // rseq_cs to zero, or we are outside a critical section and need to reset rseq_cs to zero.
        self.orig
            .write_word(rseq_cs_ptr_ptr, 0)
            .context("Failed to override rseq CS pointer to 0")?;

        let mut rseq_cs_data = MaybeUninit::<rseq_cs>::uninit();
        self.orig
            .read_memory(rseq_cs_ptr, unsafe {
                MaybeUninit::slice_assume_init_mut(rseq_cs_data.as_bytes_mut())
            })
            .context("Failed to read rseq CS data")?;
        let rseq_cs_data = unsafe { rseq_cs_data.assume_init() };

        // This pointer is the address of the syscall instruction that triggered suspension. (At
        // least, that's what the caller of collect_rseq is supposed to guarantee.) We simulate what
        // *should* have happened if a preemption was caused just before the syscall, i.e. at this
        // very IP.
        let ip = cloned_registers.get_instruction_pointer();

        if (ip as u64).wrapping_sub(rseq_cs_data.start_ip) < rseq_cs_data.post_commit_offset {
            // We are inside the critical section. A syscall instruction in a critical section is
            // typically UB--unless it's the last instruction, in which case it's just fine! Thus,
            // get our hands off kill(SIGSEGV) and faithfully update the continuation IP.
            cloned_registers.set_instruction_pointer(rseq_cs_data.abort_ip as usize);
        }

        Ok(())
    }

    fn collect_pending_signals(&mut self) -> Result<()> {
        // This detects all pending signals, including their attached data (this is critical for
        // realtime signals, but also important for e.g. SIGSEGV). This is inherently racy, but we
        // have masked all signals, so asynchronous notifications cannot arrive.
        let per_thread = self
            .orig
            .get_pending_signals(tracing::SignalQueue::PerThread)?;
        let per_process = self
            .orig
            .get_pending_signals(tracing::SignalQueue::PerProcess)?;
        // This should be infallible given the rlimit set in running
        ensure!(
            per_thread.len() <= MAX_PENDING_SIGNALS,
            "Too many pending signals"
        );
        ensure!(
            per_process.len() <= MAX_PENDING_SIGNALS,
            "Too many pending signals"
        );
        self.stemcell_state.pending_signals.count_per_thread = per_thread.len();
        self.stemcell_state.pending_signals.count_per_process = per_process.len();
        // The kernel ensures there is no padding in siginfo_t and zeroes out the padding at the
        // end, thus a copy_from_slice is fine here.
        self.stemcell_state.pending_signals.pending_per_thread[..per_thread.len()]
            .copy_from_slice(&per_thread);
        self.stemcell_state.pending_signals.pending_per_process[..per_process.len()]
            .copy_from_slice(&per_process);

        Ok(())
    }

    fn unchain_orig(&mut self) -> Result<()> {
        // If we are close to ML, we wish to let the parasite perform work anyway. We could just
        // pretend OOM happened, but that's not fair to the user process. Indeed, the kernel avoids
        // doing any user-accountable allocations in the background, and many syscalls don't alloc
        // either. Therefore, "allocate as much memory as possible, do heavy computations and then
        // deallocate in one go" is more or less valid.
        //
        // Therefore, we might need to increase ML in some rare cases. We decided to *always* update
        // ML to current use plus a bit of memory for the parasite so that this code is tested more
        // thoroughly. How much memory do we allocate? PARASITE_MEMORY_SIZE should suffice, but the
        // kernel might need additional pages for its memory management, e.g. to allocate page
        // tables or VMAs. For simplicity, add 128k. On 64k-page kernels, that rounds the parasite
        // up to 64k, and then adds 64k more for page table entries. If it works for 64k page size,
        // it'll work for 4k page size too.
        const KERNEL_ALLOCATION_OVERHEAD: usize = 128 * 1024;
        let memory_use = self
            .orig_cgroup
            .get_memory_use()
            .context("Failed to get memory use")?;
        self.orig_cgroup
            .set_memory_limit(memory_use + PARASITE_MEMORY_SIZE + KERNEL_ALLOCATION_OVERHEAD)
            .context("Failed to update ML")?;

        // The user program may have configured rlimits to enforce limits we might want to break. We
        // virtualize hard rlimits, so it shouldn't be a problem to raise the necessary limits to
        // infinity.
        for resource in [
            libc::RLIMIT_AS,
            libc::RLIMIT_CPU,
            libc::RLIMIT_DATA,
            libc::RLIMIT_RTTIME,
        ] {
            self.orig
                .set_rlimit(
                    resource,
                    libc::rlimit {
                        rlim_cur: libc::RLIM_INFINITY,
                        rlim_max: libc::RLIM_INFINITY,
                    },
                )
                .context("Failed to raise rlimit to infinity")?;
        }

        Ok(())
    }

    fn infect_orig(&mut self) -> Result<()> {
        log!("Infecting original process");

        // mmap an rwx segment
        self.inject_location = self
            .orig
            .exec_syscall(
                syscall!(mmap(
                    0,
                    // Also reserve memory for stemcell
                    PARASITE_MEMORY_SIZE.max(STEMCELL_MEMORY_SIZE),
                    PROT_READ | PROT_WRITE | PROT_EXEC,
                    MAP_PRIVATE | MAP_ANONYMOUS,
                    -1,
                    0
                )),
                self.options.inside_syscall,
            )
            .context("Failed to mmap parasite segment")?;
        log!("Found free space at 0x{:x}", self.inject_location);

        // Load code
        self.orig
            .write_memory(self.inject_location, PARASITE)
            .context("Failed to write parasite segment")?;

        // Reset processor stack (direction flag, x87 state, etc.). This should prevent the original
        // process from configuring the CPU in a way the parasite doesn't expect
        let regs = self.orig.registers_mut()?;
        regs.zero_out();
        // Call _start() with a valid stack
        regs.set_instruction_pointer(self.inject_location);
        // Put stack pointer to incorrect value to not fuck up user memory
        regs.set_stack_pointer(0xdeadbeef00000000);
        // This relies on the fact that segment registers point at GDT, which is shared between all
        // processes
        regs.copy_segment_regs();
        Ok(())
    }

    fn collect_info_via_parasite(&mut self) -> Result<()> {
        log!("Running parasite in original process");

        // We want the parasite to execute some syscalls in the original process. Unfortunately,
        // these syscalls include ones blocked by seccomp due to the nature of prefork, so we have
        // to explicitly allow them via ptrace.

        self.orig.resume()?;

        wait_for_raised_sigstop(self.orig, false)
            .context("Failed to wait for raise(SIGSTOP) in parasite")?;

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

        copy_field_by_field!(
            parasite_state => self.stemcell_state,
            {
                alternative_stack,
                arch_prctl_options,
                itimers,
                robust_list,
                signal_handlers,
                personality,
                thp_options,
                tid_address,
                umask,
            }
        );
        self.stemcell_state.mm_options.brk = parasite_state.program_break;

        Ok(())
    }

    fn collect_file_descriptors(&mut self) -> Result<()> {
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
            if fd < 3 || self.options.ignore_fd == Some(fd) {
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
                            i32::from_str_radix(value, 8)
                                .context("'flags' is not an octal number")?,
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

            let stemcell_state: &mut StemcellState = &mut self.stemcell_state;
            let saved_fd = stemcell_state
                .file_descriptors
                .fds
                .get_mut(stemcell_state.file_descriptors.count)
                .context("Too many file descriptors")?;
            stemcell_state.file_descriptors.count += 1;

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
        copy_field_by_field!(
            stat => self.stemcell_state.mm_options,
            {
                start_code,
                end_code,
                start_data,
                end_data,
                start_brk,
                // brk is filled by parasite
                start_stack,
                arg_start,
                arg_end,
                env_start,
                env_end,
                auxv: 0,
                auxv_size: 0,
                exe_fd: -1,
            }
        );
        Ok(())
    }

    fn collect_timers(&mut self) -> Result<()> {
        let timers = self
            .orig
            .get_timers()
            .context("Failed to get original process timers")?;
        // XXX This is plain cringe.
        ensure!(timers.len() <= 64, "Too many timers");

        self.stemcell_state.timers.timer_count = timers.len();
        for (state_timer, timer) in self.stemcell_state.timers.timers.iter_mut().zip(timers) {
            copy_field_by_field!(
                timer => *state_timer,
                {id, signal, sigev_value, mechanism, target, clock_id}
            );
        }

        Ok(())
    }

    fn translate_memory_maps(&mut self, memory_maps: &[tracing::MemoryMap]) -> Result<()> {
        self.stemcell_state.memory_maps.orig_mem_fd = self.transferred_fds.len() as RawFd;
        self.transferred_fds.push(
            self.orig
                .get_mem()
                .try_clone()
                .context("Failed to clone /proc/.../mem of original process")?
                .into(),
        );

        self.stemcell_state.memory_maps.orig_pagemap_fd = self.transferred_fds.len() as RawFd;
        self.transferred_fds.push(
            self.orig
                .open_pagemap()
                .context("Failed to open /proc/.../pagemap of original process")?
                .into(),
        );

        let mut file_indices = HashMap::new();

        for map in memory_maps {
            // This segment has the same address in all processes
            if map.desc == "[vsyscall]" {
                continue;
            }
            // Although [vvar] and [vdso] are typically mapped, they are pretty much unusable, which
            // is why we disabled them before (or, rather, made them inaccessible to the dynamic
            // linker). Mapping VDSO is hard on platforms other than x86, and if no one uses it, we
            // might get away with not copying it
            if map.desc == "[vvar]" || map.desc == "[vdso]" {
                continue;
            }

            let stemcell_state: &mut StemcellState = &mut self.stemcell_state;
            let alloced = stemcell_state
                .memory_maps
                .maps
                .get_mut(stemcell_state.memory_maps.count)
                .context("Too many memory mappings")?;
            stemcell_state.memory_maps.count += 1;

            alloced.base = map.base;
            alloced.end = map.end;
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
                alloced.prot |= -0x80000000;
            }

            // We used to transform private file-backend mappings to *anonymous* mappings on
            // suspend. This was not entirely *correct*, e.g. the map gets denolted differently in
            // procfs, but it lead to a significant increase of performance (10% on Python A+B),
            // because Linux supports THP for anonymous pages but not for file-backed mappings.
            // Using THP would significantly decrease the number of page table entires to
            // allocate/deallocate during fork/exit, and these two syscall take a large portion of
            // time in short-lived tasks.
            //
            // Unfortunately, we had to disable this later when an accounting problem turned up.
            // Suppose we map the same relatively large file 60000 times as PROT_READ. As the pages
            // are never written to, they are deduplicated and take little space. However, if we
            // transform the file-backed mapping to an anonymous mapping, this deduplication is lost
            // and we OOM during suspend, when we read the file into memory for the Nth time.
            //
            // This set-back is compensated by existence of CONFIG_READ_ONLY_THP_FOR_FS, which lets
            // file-backed mappings use THP too. It applies to non-executable mappings only since
            // v6.8, however. And, mind you, it doesn't resolve the problem *completely*, as this
            // adds the requirement that 'base' and 'offset' are congruent. However, this sort of
            // performance loss (or complexity increase) if perhaps reasonable for increased safety.
            //
            // If we ever find a better work around (and update the code in memory_maps.hpp too!!),
            // toggle this constant.
            const REMAP_PRIVATE_AS_ANONYMOUS: bool = false;

            if map.inode == 0 || (REMAP_PRIVATE_AS_ANONYMOUS && !map.shared) {
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
            match self.orig.get_memory_mapped_file_path(map)? {
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

        self.stemcell_state.controlling_fd = self.transferred_fds.len() as i32;
        self.transferred_fds.push(rx);

        self.control_tx = Some(tx);

        Ok(())
    }

    fn collect_rlimits(&self) -> Result<[libc::rlimit; 16]> {
        // This does not *quite* cover RLIMIT_CPU. Say, if a process spends half a second in
        // prefork, SIGXCPU will fire half a second later than expected. This is a bad thing if
        // someone uses SIGXCPU to abort computations just before TLE. This should be a rare case,
        // as this is not applicable to the typical time limit of 1 second, and there are more
        // popular ways to trigger a signal upon timer expiration, both simpler (e.g. alarm(2)) and
        // more precise (e.g. setitimer(2), which uses the same timer with ITIMER_PROF). An accurate
        // emulation of RLIMIT_CPU is complicated at best, so it'll likely stay a TODO until anyone
        // halloos.
        std::array::try_from_fn(|i| {
            Ok(libc::rlimit {
                rlim_cur: tracing::get_rlimit(self.orig.get_pid(), i as i32)
                    .context("Failed to get rlimit")?
                    .rlim_cur,
                rlim_max: self.hard_rlimits[i],
            })
        })
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
        self.patch_transferred_fds(&transferred_fds);

        if let Some(error) = ours
            .recv()
            .context("Failed to read an error from the child")?
        {
            bail!("{error}");
        }

        let wait_status =
            wait::waitpid(master_pid, None).context("Failed to waitpid for process")?;
        let wait::WaitStatus::Stopped(_, signal::Signal::SIGSTOP) = wait_status else {
            bail!("waitpid returned unexpected status at stemcell: {wait_status:?}");
        };

        let master = tracing::TracedProcess::new(master_pid)?;
        master.init().context("Failed to init master")?;
        self.master = Some(master);

        Ok(())
    }

    fn patch_transferred_fds(&mut self, fds: &[RawFd]) {
        log!("Patching transferred fds");

        self.stemcell_state.memory_maps.orig_mem_fd =
            fds[self.stemcell_state.memory_maps.orig_mem_fd as usize];
        self.stemcell_state.memory_maps.orig_pagemap_fd =
            fds[self.stemcell_state.memory_maps.orig_pagemap_fd as usize];

        let mm_count = self.stemcell_state.memory_maps.count;
        for map in &mut self.stemcell_state.memory_maps.maps[..mm_count] {
            if map.fd != -1 {
                map.fd = fds[map.fd as usize];
            }
        }

        let fd_count = self.stemcell_state.file_descriptors.count;
        for fd in &mut self.stemcell_state.file_descriptors.fds[..fd_count] {
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

        self.stemcell_state.controlling_fd = fds[self.stemcell_state.controlling_fd as usize];
    }

    fn restore_via_master(&mut self) -> Result<()> {
        log!("Uploading data to master");

        let master = self.master.as_mut().unwrap();

        self.stemcell_state.end_of_memory_space = master
            .get_memory_maps()
            .context("Failed to read memory maps of master")?
            .iter()
            .filter(|map| map.desc != "[vsyscall]")
            .last()
            .context("No memory maps in master")?
            .end;

        master
            .write_memory(self.inject_location + STEMCELL_STATE_OFFSET, unsafe {
                self.stemcell_state.bytes()
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
            master.resume_signal(libc::SIGKILL)?;
            wait_for_sigkill(master)?;
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
        let wait_status = process.wait()?;
        log!("Got wait status {wait_status:?}");

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
                    let ip = process.registers_ref()?.get_instruction_pointer();
                    log!("SIGSTOP at {ip:x}");
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
                    wait_for_sigkill(process)?;
                    bail_signal(info)?;
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

fn bail_signal(info: siginfo_t) -> Result<!> {
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

fn wait_for_sigkill(process: &mut tracing::TracedProcess) -> Result<()> {
    let wait_status = process.wait()?;
    ensure!(
        matches!(wait_status, system::WaitStatus::Signaled(_, libc::SIGKILL)),
        "Expected SIGKILL, got {wait_status:?}"
    );
    Ok(())
}

#[crossmist::func]
fn prefork_master(
    mut pipe: crossmist::Sender<String>,
    inject_location: usize,
    mut transferred_fds: Vec<OwnedFd>,
    forbidden_transferred_fds: HashSet<RawFd>,
    mut transferred_fds_tx: Sender<Vec<RawFd>>,
) {
    let result: Result<!> = try {
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
            *chunk =
                (usize::from_ne_bytes(*chunk) - 0xdeadbeef0000 + inject_location).to_ne_bytes();
        }

        let stemcell = system::make_memfd("stemcell", &stemcell_elf)?;

        // This mostly repeats the code in running::executor_worker
        timens::disable_native_instructions()
            .context("Failed to disable native timens instructions")?;
        tracing::apply_seccomp_filter(false).context("Failed to apply seccomp filter")?;

        // We cannot set NO_NEW_PRIVS here, nor initiate PTRACE_TRACEME, because that's going to
        // break UIDs on execve. There's no *good* reason they break UIDs, but due to a quirk in
        // Linux (bug. it's a bug. it's not POSIX compliant in the slightest.), those have to be
        // delayed until stemcell is executed. Otherwise, Linux will believe *something* might be
        // insecure, and reset eUID to rUID. Indeed, eUID != rUID is interpreted as an indicator of
        // a SUID executable, which it clearly isn't, and NO_NEW_PRIVS disables that. Even without
        // NO_NEW_PRIVS, Linux recognizes that the stemcell's ptracer (i.e. the manager) does not
        // hold CAP_SYS_PTRACE in the user namespace, and tries to be "helpful" again. (I'm not sure
        // why it thinks it doesn't hold CAP_SYS_PTRACE, actually, because root is supposed to hold
        // all capabilities, but here we are.)

        // We don't immediately switch all UIDs to the user, as we don't want the stemcell children
        // to touch the stemcell. Instead, we only switch the *effective* UID to the user UID, and
        // make real and saved UIDs point at another entity. This way, no one can signal the
        // stemcell or hurt it in any other way, because its real/saved UID is not the user UID, but
        // it can still switch to user UID completely afterwards, because it retains it as an
        // effective UID.
        userns::drop_privileges_untouchable().context("Failed to drop privileges")?;

        let argv = [CStr::from_bytes_with_nul(b"stemcell\0").unwrap()];
        let envp: [&CStr; 0] = [];
        match unistd::fexecve(stemcell.as_raw_fd(), &argv, &envp).context("execv failed")? {}
    };

    pipe.send(&format!("{:?}", result.into_err()))
        .expect("Failed to report error to parent");
}
