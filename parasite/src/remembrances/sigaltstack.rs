use crate::{ensure, libc, anyhow::Result, entry::is_interval_safe};

#[repr(C)]
pub struct stack_t {
    ss_sp: usize,
    ss_flags: i32,
    ss_size: usize,
}

pub fn in_orig() -> Result<stack_t> {
    let mut stack: stack_t = stack_t {
        ss_sp: 0,
        ss_flags: 0,
        ss_size: 0,
    };
    libc::sigaltstack(0, &mut stack)?;
    Ok(stack)
}

pub fn in_master(stack: stack_t) -> Result<()> {
    const SS_DISABLE: i32 = 2;
    if stack.ss_flags & SS_DISABLE == 0 {
        ensure!(is_interval_safe(stack.ss_sp..stack.ss_sp.saturating_add(stack.ss_size)), "sigaltstack intersects parasite");
        libc::sigaltstack(&stack, 0)?;
    }
    Ok(())
}
