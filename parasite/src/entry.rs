use crate::{
    anyhow::{Context, Result},
    libc, remembrances,
    types::iovec,
};
use core::ops::Range;

#[repr(C)]
pub struct StartInformation {
    pub orig_pid: u32,
    pub relocate_from: usize,
    pub relocate_to: usize,
    pub prog_size: usize,
    pub rseq_info: Option<RSeqInfo>,
}

#[repr(C)]
pub struct RSeqInfo {
    pub rseq_abi_pointer: usize,
    pub rseq_abi_size: u32,
    pub flags: u32,
    pub signature: u32,
    pub rseq_cs: usize,
}

#[no_mangle]
pub static mut START_INFORMATION: StartInformation = StartInformation {
    orig_pid: 0,
    relocate_from: 0,
    relocate_to: 0,
    prog_size: 0,
    rseq_info: None,
};

#[no_mangle]
pub fn checkpoint() -> Result<()> {
    let arch_prctl_options =
        remembrances::arch_prctl_options::in_orig().context("Failed to save arch_prctl options")?;
    let itimers = remembrances::itimers::in_orig().context("Failed to save interval timers")?;
    let mm_options =
        remembrances::mm_options::in_orig().context("Failed to save memory map options")?;
    remembrances::pending_signals::in_orig().context("Failed to save pending signals")?;
    let personality = remembrances::personality::in_orig().context("Failed to save personality")?;
    let sigaltstack = remembrances::sigaltstack::in_orig().context("Failed to save sigaltstack")?;
    let signal_handlers =
        remembrances::signal_handlers::in_orig().context("Failed to save signal handlers")?;
    let signal_mask = remembrances::signal_mask::in_orig().context("Failed to save signal mask")?;
    let thp_options = remembrances::thp_options::in_orig()
        .context("Failed to save transparent huge pages options")?;
    let tid_address = remembrances::tid_address::in_orig().context("Failed to save TID address")?;
    let timers = remembrances::timers::in_orig().context("Failed to save POSIX timers")?;
    let umask = remembrances::umask::in_orig().context("Failed to save umask")?;

    teleport()?;

    remembrances::arch_prctl_options::in_master(arch_prctl_options)
        .context("Failed to restore arch_prctl options")?;
    remembrances::cwd::in_master().context("Failed to copy working directory")?;
    remembrances::fds::in_master().context("Failed to copy file descriptors")?;
    remembrances::itimers::in_master(itimers).context("Failed to restore interval timers")?;
    remembrances::memory_maps::in_master().context("Failed to copy memory maps")?;
    remembrances::mm_options::in_master(mm_options)
        .context("Failed to restore memory map options")?;
    remembrances::personality::in_master(personality).context("Failed to restore personality")?;
    remembrances::resource_limits::in_master().context("Failed to copy resource limits")?;
    remembrances::robust_list::in_master().context("Failed to copy robust futex list")?;
    remembrances::rseq::in_master().context("Failed to restore rseq")?;
    remembrances::sigaltstack::in_master(sigaltstack).context("Failed to restore sigaltstack")?;
    remembrances::signal_handlers::in_master(signal_handlers)
        .context("Failed to restore signal handlers")?;
    remembrances::signal_mask::in_master(signal_mask).context("Failed to restore signal mask")?;
    remembrances::thp_options::in_master(thp_options)
        .context("Failed to restore transparent huge pages options")?;
    remembrances::tid_address::in_master(tid_address).context("Failed to restore TID address")?;
    remembrances::umask::in_master(umask).context("Failed to restore umask")?;

    fork_loop()?;
}

#[no_mangle]
pub fn start() -> Result<()> {
    unsafe {
        libc::mremap(
            START_INFORMATION.relocate_from,
            START_INFORMATION.prog_size,
            START_INFORMATION.prog_size,
            libc::MREMAP_FIXED | libc::MREMAP_MAYMOVE,
            START_INFORMATION.relocate_to,
        )
        .context("Failed to relocate")?;
    };
    Ok(())
}

fn teleport() -> Result<()> {
    unsafe {
        libc::kill(0, libc::SIGUSR1)?;
        let iov = iovec {
            iov_base: START_INFORMATION.relocate_to as *const u8,
            iov_len: START_INFORMATION.prog_size,
        };
        libc::process_vm_readv(START_INFORMATION.orig_pid, &iov, 1, &iov, 1, 0)
            .context("Failed to process_vm_readv")?;
    }
    Ok(())
}

fn fork_loop() -> Result<!> {}

pub fn is_interval_safe(interval: Range<usize>) -> bool {
    unsafe {
        interval.start >= START_INFORMATION.relocate_to + START_INFORMATION.prog_size
            || interval.end <= START_INFORMATION.relocate_to
    }
}
