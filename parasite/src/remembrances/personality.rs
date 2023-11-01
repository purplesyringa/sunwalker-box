use crate::{libc, anyhow::Result};

// Holy echopraxia

pub fn in_orig() -> Result<isize> {
    libc::personality(0xffffffffu32)
}

pub fn in_master(personality: isize) -> Result<()> {
    libc::personality(personality)?;
    Ok(())
}