use crate::{anyhow::Result, libc};

pub fn in_orig() -> Result<u64> {
    let mut sigset = 0;
    libc::rt_sigprocmask(libc::SIG_BLOCK, 0, &mut sigset, 8)?;
    Ok(sigset)
}

pub fn in_master(sigset: u64) -> Result<()> {
    libc::rt_sigprocmask(libc::SIG_SETMASK, &sigset, 0, 8)?;
    Ok(())
}
