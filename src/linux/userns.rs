use crate::linux::ids::*;
use anyhow::{Context, Result};
use rustix::thread::{Pid, UnshareFlags};

pub fn enter_user_namespace() -> Result<()> {
    // Start a subprocess which will give us the right uid_map and gid_map
    let (mut tx, rx) = crossmist::channel::<()>().context("Failed to create channel")?;
    let child = configure_ns.spawn(rx).context("Failed to start child")?;

    unsafe { rustix::thread::unshare_unsafe(UnshareFlags::NEWUSER) }
        .context("Failed to unshare user namespace")?;

    tx.send(&()).context("Failed to trigger child")?;

    child.join().context("Child didn't terminate gracefully")?;

    // Become in-sandbox root
    rustix::thread::set_thread_uid(INTERNAL_ROOT_UID).context("Failed to setuid to root")?;
    rustix::thread::set_thread_gid(INTERNAL_ROOT_GID).context("Failed to setgid to root")?;

    Ok(())
}

#[crossmist::func]
fn configure_ns(rx: crossmist::Receiver<()>) {
    if let Err(e) = configure_ns_impl(rx) {
        eprintln!("{e:?}");
        std::process::exit(1);
    }
}

fn configure_ns_impl(mut rx: crossmist::Receiver<()>) -> Result<()> {
    rx.recv()
        .context("Failed to recv")?
        .context("Parent terminated")?;

    let ppid = Pid::as_raw(rustix::process::getppid());

    // Fill uid/gid maps
    std::fs::write(
        format!("/newroot/proc/{ppid}/uid_map"),
        format!(
            "{} {} 1\n{} {} 1\n{} {} 1\n",
            INTERNAL_ROOT_UID.as_raw(),
            EXTERNAL_ROOT_UID.as_raw(),
            INTERNAL_USER_UID.as_raw(),
            EXTERNAL_USER_UID.as_raw(),
            NOBODY_UID.as_raw(),
            NOBODY_UID.as_raw()
        ),
    )
    .context("Failed to fill uid_map")?;

    std::fs::write(format!("/newroot/proc/{ppid}/setgroups"), "allow\n")
        .context("Failed to fill setgroups")?;

    std::fs::write(
        format!("/newroot/proc/{ppid}/gid_map"),
        format!(
            "{} {} 1\n{} {} 1\n{} {} 1\n",
            INTERNAL_ROOT_GID.as_raw(),
            EXTERNAL_ROOT_GID.as_raw(),
            INTERNAL_USER_GID.as_raw(),
            EXTERNAL_USER_GID.as_raw(),
            NOGRP_GID.as_raw(),
            NOGRP_GID.as_raw()
        ),
    )
    .context("Failed to fill gid_map")?;

    Ok(())
}

pub fn drop_privileges() -> Result<()> {
    // Calling setuid() resets the "dumpable" attribute of the calling process, which in turn
    // disables ptracing and makes its /proc/<pid> subdirectory root-owned, which guarantees that a
    // malicious program cannot mess with the process except by sending signals to it. For the short
    // period of time between clone(2) and execve(2), this is not a problem. It would be a problem
    // in some other cases though, e.g. if we called drop_privileges() in a manager process, because
    // that would allow the child to send SIGSTOP to circumvent time limit, or to send SIGKILL,
    // which would confuse the system.
    rustix::thread::set_thread_groups(&[INTERNAL_USER_GID]).context("Failed to setgroups")?;
    rustix::thread::set_thread_gid(INTERNAL_USER_GID).context("Failed to setgid to user")?;
    rustix::thread::set_thread_uid(INTERNAL_USER_UID).context("Failed to setuid to user")?;
    Ok(())
}
