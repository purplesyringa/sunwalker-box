use crate::{anyhow::Result, ensure, libc};

pub fn in_orig() -> Result<()> {
    // TODO: we'd better remove this restriction
    let mut sigset = 0usize;
    libc::rt_sigpending(&mut sigset, 8)?;
    ensure!(
        sigset == 0,
        "sunwalker cannot suspend processes with pending signals"
    );
    Ok(())
}
