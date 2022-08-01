use libc::CLONE_NEWNS;

pub fn unshare_mountns() -> std::io::Result<()> {
    if unsafe { libc::unshare(CLONE_NEWNS) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}
