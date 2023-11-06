use crate::{anyhow::Result, libc};

pub fn in_orig() -> Result<isize> {
    libc::umask(0)
}

pub fn in_master(umask: isize) -> Result<()> {
    libc::umask(umask)?;
    Ok(())
}
