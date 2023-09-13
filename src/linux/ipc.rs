use crate::linux::system;
use anyhow::{Context, Result};
use nix::{
    libc,
    libc::{c_int, pid_t, CLONE_NEWIPC},
    sched,
};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::os::unix::fs::PermissionsExt;

pub fn unshare_ipc_namespace() -> Result<()> {
    if unsafe { libc::unshare(CLONE_NEWIPC) } != 0 {
        return Err(std::io::Error::last_os_error()).context("unshare() failed");
    }
    Ok(())
}

pub fn mount_mqueue(path: &str) -> Result<()> {
    system::mount("mqueue", path, "mqueue", 0, None)
        .with_context(|| format!("Failed to mount mqueue on {path}"))?;
    // rwxrwxrwt
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o1777))
        .with_context(|| format!("Failed to make {path} world-writable"))?;
    Ok(())
}

pub fn join_process_ipc_namespace(pid: pid_t) -> Result<()> {
    let ipc = File::open(format!("/newroot/proc/{pid}/ns/ipc"))?;
    sched::setns(ipc, sched::CloneFlags::CLONE_NEWIPC)?;
    Ok(())
}

// Handling these in namespaces requires Linux 5.19+ (linux@1f5c135ee509e89e0cc274333a65f73c62cb16e5)
pub fn get_next_id(name: &str) -> Result<isize> {
    std::fs::read_to_string(format!("/proc/sys/kernel/{name}_next_id"))
        .with_context(|| format!("Failed to get {name}_next_id"))?
        .trim()
        .parse()
        .context("Invalid number format")
}
pub fn set_next_id(name: &str, id: isize) -> Result<()> {
    std::fs::write(
        format!("/proc/sys/kernel/{name}_next_id"),
        format!("{id}\n"),
    )
    .with_context(|| format!("Failed to set {name}_next_id"))
}

pub fn reset() -> Result<()> {
    // The IPC namespace is critical to clean up correctly, because creating an IPC namespace in the
    // kernel is terribly slow, and *deleting* it actually happens asynchronously. This basically
    // means that if we create and drop IPC namespaces quickly enough, the deleting queue will
    // overflow and we won't be able to do any IPC operation (including creation of an IPC
    // namespace) for a while--something to avoid at all costs.

    // POSIX message queues are stored in /newroot/dev/mqueue as files, which we can simply unlink.
    for entry in
        std::fs::read_dir("/newroot/dev/mqueue").context("Failed to readdir /newroot/dev/mqueue")?
    {
        let entry = entry.context("Failed to readdir /newroot/dev/mqueue")?;
        std::fs::remove_file(entry.path())
            .with_context(|| format!("Failed to rm {:?}", entry.path()))?;
    }

    // Clean up System V message queues
    reset_sysv_set("msg", "message queue", |id| unsafe {
        libc::msgctl(id, libc::IPC_RMID, std::ptr::null_mut())
    })?;
    reset_sysv_set("sem", "semaphore set", |id| unsafe {
        libc::semctl(id, 0, libc::IPC_RMID)
    })?;
    reset_sysv_set("shm", "shared memory segment", |id| unsafe {
        libc::shmctl(id, libc::IPC_RMID, std::ptr::null_mut())
    })?;

    Ok(())
}

fn reset_sysv_set(name: &str, long_name: &str, remover: fn(c_int) -> c_int) -> Result<()> {
    // Delete all message queues/semaphore sets/shared memory segments
    let path = format!("/proc/sysvipc/{name}");

    let file = File::open(&path).with_context(|| format!("Failed to open {path}"))?;

    let mut ids: Vec<c_int> = Vec::new();

    // Skip header
    for line in BufReader::new(file).lines().skip(1) {
        let line = line.with_context(|| format!("Failed to read {path}"))?;
        let mut it = line.trim().split_ascii_whitespace();

        it.next()
            .with_context(|| format!("Invalid format of {path}"))?;

        let id = it
            .next()
            .with_context(|| format!("Invalid format of {path}"))?
            .parse()
            .with_context(|| format!("Invalid format of id in {path}"))?;

        ids.push(id);
    }

    for id in ids {
        if remover(id) == -1 {
            return Err(std::io::Error::last_os_error())
                .with_context(|| format!("Failed to delete System V {long_name} #{id}"));
        }
    }

    Ok(())
}
