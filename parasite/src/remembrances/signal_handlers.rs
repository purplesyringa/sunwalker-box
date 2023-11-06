use crate::{anyhow::Result, libc};

// FIXME: only x86-64
#[derive(Clone, Copy)]
#[repr(C)]
pub struct sigaction {
    sa_handler: usize,
    sa_mask: u64,
    sa_flags: usize,
    sa_restorer: usize,
}

pub fn in_orig() -> Result<[sigaction; 64]> {
    let mut actions = [sigaction {
        sa_handler: 0,
        sa_mask: 0,
        sa_flags: 0,
        sa_restorer: 0,
    }; 64];
    for signum in 1..=64 {
        if signum == libc::SIGKILL || signum == libc::SIGSTOP {
            continue;
        }
        libc::rt_sigaction(
            signum,
            0,
            unsafe { actions.get_unchecked_mut(signum as usize - 1) },
            8,
        )?;
    }
    Ok(actions)
}

pub fn in_master(actions: [sigaction; 64]) -> Result<()> {
    for signum in 1..=64 {
        if signum == libc::SIGKILL || signum == libc::SIGSTOP {
            continue;
        }
        libc::rt_sigaction(
            signum,
            unsafe { actions.get_unchecked(signum as usize - 1) },
            0,
            8,
        )?;
    }
    Ok(())
}
