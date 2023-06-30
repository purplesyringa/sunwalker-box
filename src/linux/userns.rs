use crate::linux::ids::*;
use anyhow::{Context, Result};
use nix::{libc, libc::CLONE_NEWUSER, unistd};

pub fn enter_user_namespace() -> Result<()> {
    // Start a subprocess which will give us the right uid_map and gid_map
    let (mut tx, rx) = multiprocessing::channel::<()>().context("Failed to create channel")?;
    let mut child = configure_ns.spawn(rx).context("Failed to start child")?;

    if unsafe { libc::unshare(CLONE_NEWUSER) } != 0 {
        return Err(std::io::Error::last_os_error()).context("unshare() failed");
    }

    tx.send(&()).context("Failed to trigger child")?;

    child.join().context("Child didn't terminate gracefully")?;

    // Become in-sandbox root
    nix::unistd::setuid(nix::unistd::Uid::from_raw(INTERNAL_ROOT_UID))
        .context("Failed to setuid to root")?;
    nix::unistd::setgid(nix::unistd::Gid::from_raw(INTERNAL_ROOT_GID))
        .context("Failed to setgid to root")?;

    Ok(())
}

#[multiprocessing::func]
fn configure_ns(mut rx: multiprocessing::Receiver<()>) {
    rx.recv()
        .expect("Failed to recv")
        .expect("Parent terminated");

    let ppid = nix::unistd::getppid();

    // Fill uid/gid maps
    std::fs::write(
        format!("/newroot/proc/{ppid}/uid_map"),
        format!(
            "{INTERNAL_ROOT_UID} {EXTERNAL_ROOT_UID} 1\n{INTERNAL_USER_UID} {EXTERNAL_USER_UID} \
             1\n{NOBODY_UID} {NOBODY_UID} 1\n"
        ),
    )
    .expect("Failed to fill uid_map");

    std::fs::write(format!("/newroot/proc/{ppid}/setgroups"), "allow\n")
        .expect("Failed to fill setgroups");

    std::fs::write(
        format!("/newroot/proc/{ppid}/gid_map"),
        format!(
            "{INTERNAL_ROOT_GID} {EXTERNAL_ROOT_GID} 1\n{INTERNAL_USER_GID} {EXTERNAL_USER_GID} \
             1\n{NOGRP_GID} {NOGRP_GID} 1\n"
        ),
    )
    .expect("Failed to fill gid_map");
}

pub fn drop_privileges() -> Result<()> {
    // Calling setuid() resets the "dumpable" attribute of the calling process, which in turn
    // disables ptracing and makes its /proc/<pid> subdirectory root-owned, which guarantees that a
    // malicious program cannot mess with the process except by sending signals to it. For the short
    // period of time between clone(2) and execve(2), this is not a problem. It would be a problem
    // in some other cases though, e.g. if we called drop_privileges() in a manager process, because
    // that would allow the child to send SIGSTOP to circumvent time limit, or to send SIGKILL,
    // which would confuse the system.
    unistd::setgroups(&[unistd::Gid::from_raw(INTERNAL_USER_GID)])
        .context("Failed to setgroups")?;
    if unsafe { libc::setgid(INTERNAL_USER_GID) } != 0 {
        return Err(std::io::Error::last_os_error()).context("Failed to setgid");
    }
    if unsafe { libc::setuid(INTERNAL_USER_UID) } != 0 {
        return Err(std::io::Error::last_os_error()).context("Failed to setuid");
    }
    Ok(())
}
