use crate::{anyhow::Result ,libc, entry::{START_INFORMATION, is_interval_safe}, ensure};

pub fn in_master() -> Result<()> {
    let mut head = 0usize;
    let mut len = 0usize;
    libc::get_robust_list(unsafe { START_INFORMATION.orig_pid }, &mut head, &mut len)?;
    ensure!(is_interval_safe(head..head.saturating_add(len)), "Fobust futex list intersects parasite");
    libc::set_robust_list(head, len)?;
    Ok(())
}
