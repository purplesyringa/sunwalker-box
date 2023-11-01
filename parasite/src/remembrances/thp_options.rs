use crate::{anyhow::Result, libc};

pub fn in_orig() -> Result<isize> {
    libc::prctl(libc::PR_GET_THP_DISABLE, 0, 0, 0, 0)
}

pub fn in_master(value: isize) -> Result<()> {
    libc::prctl(libc::PR_SET_THP_DISABLE, value, 0, 0, 0)?;
    Ok(())
}
