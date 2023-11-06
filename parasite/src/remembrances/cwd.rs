use crate::{anyhow::Result, entry::START_INFORMATION, format, libc};

pub fn in_master() -> Result<()> {
    let cwd = format!(b"/proc/", unsafe { START_INFORMATION.orig_pid }, b"/cwd\0");
    libc::chdir(cwd.as_ref())?;
    Ok(())
}
