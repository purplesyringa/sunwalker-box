use rustix::fs::MemfdFlags;
use rustix::io::{Errno, Result};
use rustix::mount::MountFlags;
use rustix::process::{Pid, Signal, WaitOptions};
use std::fs::File;
use std::io::Write;
use std::path::Path;

pub fn remount_readonly<P: AsRef<Path>>(path: P) -> Result<()> {
    // If a filesystem was mounted with NOSUID/NODEV/NOEXEC, we won't be able to remount the
    // bind-mount without specifying those same flags. Parsing mountinfo seems slow, and this case
    // isn't going to be triggered often in production anyway, so we just use the shotgun approach
    // for now, bruteforcing the flags in the order of most likeliness.
    for flags in [
        MountFlags::empty(),
        MountFlags::NOSUID,
        MountFlags::NODEV,
        MountFlags::NOSUID | MountFlags::NODEV,
        MountFlags::NOEXEC,
        MountFlags::NOEXEC | MountFlags::NOSUID,
        MountFlags::NOEXEC | MountFlags::NODEV,
        MountFlags::NOEXEC | MountFlags::NOSUID | MountFlags::NODEV,
    ] {
        match rustix::mount::mount_remount(
            path.as_ref(),
            MountFlags::BIND | MountFlags::RDONLY | flags,
            "",
        ) {
            Err(Errno::PERM) => continue,
            result => return result,
        }
    }
    Err(Errno::PERM)
}

pub fn make_memfd(name: &str, contents: &[u8]) -> std::io::Result<File> {
    let mut file = File::from(rustix::fs::memfd_create(name, MemfdFlags::CLOEXEC)?);
    file.write_all(contents)?;
    Ok(file)
}

// We need to roll our own rustix::wait because rustix's version doesn't provide convenient API
#[derive(Debug, PartialEq)]
pub enum WaitStatus {
    Exited(Pid, i32),
    Signaled(Pid, Signal),
    Stopped(Pid, Signal),
    PtraceEvent(Pid, Signal, i32),
    PtraceSyscall(Pid),
    Continued(Pid),
    StillAlive,
}

pub fn waitpid(pid: Option<Pid>, options: WaitOptions) -> Result<WaitStatus> {
    let res = match pid {
        Some(_) => rustix::process::waitpid(pid, options),
        None => rustix::process::wait(options),
    }?;

    let Some((pid, ws)) = res else {
        return Ok(WaitStatus::StillAlive);
    };
    Ok(if ws.exited() {
        WaitStatus::Exited(pid, ws.exit_status().ok_or(Errno::INVAL)?)
    } else if ws.signaled() {
        WaitStatus::Signaled(pid, unsafe {
            Signal::from_raw_unchecked(ws.terminating_signal().ok_or(Errno::INVAL)?)
        })
    } else if ws.stopped() {
        let stopsig =
            unsafe { Signal::from_raw_unchecked(ws.stopping_signal().ok_or(Errno::INVAL)?) };
        let raw = ws.as_raw();
        if stopsig.as_raw() == Signal::TRAP.as_raw() | 0x80 {
            WaitStatus::PtraceSyscall(pid)
        } else if raw >> 16 == 0 {
            WaitStatus::Stopped(pid, stopsig)
        } else {
            WaitStatus::PtraceEvent(pid, stopsig, raw >> 16)
        }
    } else if ws.continued() {
        WaitStatus::Continued(pid)
    } else {
        return Err(Errno::INVAL);
    })
}

impl WaitStatus {
    pub fn pid(&self) -> Option<Pid> {
        match self {
            Self::Exited(pid, _)
            | Self::Signaled(pid, _)
            | Self::Stopped(pid, _)
            | Self::PtraceEvent(pid, _, _)
            | Self::PtraceSyscall(pid)
            | Self::Continued(pid) => Some(*pid),
            Self::StillAlive => None,
        }
    }
}
