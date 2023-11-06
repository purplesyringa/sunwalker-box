use crate::{anyhow::Result, ensure, entry::is_interval_safe, libc};

pub fn in_orig() -> Result<usize> {
    let mut clear_child_tid = 0usize;
    libc::prctl(libc::PR_GET_TID_ADDRESS, &mut clear_child_tid)?;
    Ok(clear_child_tid)
}

pub fn in_master(clear_child_tid: usize) -> Result<()> {
    ensure!(
        is_interval_safe(clear_child_tid..clear_child_tid + 8),
        "clear_child_tid intersects parasite"
    );
    libc::set_tid_address(clear_child_tid)?;
    Ok(())
}
