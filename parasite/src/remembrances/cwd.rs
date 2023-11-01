use crate::{util, libc,entry::START_INFORMATION, anyhow::Result};

pub fn in_master() -> Result<()> {
    let cwd = util::format_proc_path(Some(unsafe { START_INFORMATION.orig_pid }), b"/cwd");
    libc::chdir(cwd.as_ref())?;
    Ok(())
}
