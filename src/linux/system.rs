use nix::{
    libc,
    libc::{c_int, c_ulong, c_void},
    sys::memfd,
};

pub use nix::libc::{
    MNT_DETACH, MNT_EXPIRE, MNT_FORCE, MS_BIND, MS_DIRSYNC, MS_LAZYTIME, MS_MANDLOCK, MS_MOVE,
    MS_NOATIME, MS_NODEV, MS_NODIRATIME, MS_NOEXEC, MS_NOSUID, MS_PRIVATE, MS_RDONLY, MS_REC,
    MS_RELATIME, MS_REMOUNT, MS_SHARED, MS_SILENT, MS_SLAVE, MS_STRICTATIME, MS_SYNCHRONOUS,
    MS_UNBINDABLE, UMOUNT_NOFOLLOW,
};

use std::ffi::CString;
use std::io::{Error, ErrorKind, Result, Write};
use std::os::fd::FromRawFd;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::ptr::null;

pub fn to_cstring(data: &[u8]) -> Result<CString> {
    CString::new(data)
        .map_err(|e| Error::new(ErrorKind::InvalidData, format!("CString::new failed: {e}")))
}

pub fn mount<S: AsRef<Path>, T: AsRef<Path>>(
    source: S,
    target: T,
    fs_type: &str,
    flags: c_ulong,
    data: Option<&str>,
) -> Result<()> {
    let data_cstr = match data {
        Some(s) => Some(to_cstring(s.as_bytes())?),
        None => None,
    };
    let res = unsafe {
        libc::mount(
            to_cstring(source.as_ref().as_os_str().as_bytes())?.as_ptr(),
            to_cstring(target.as_ref().as_os_str().as_bytes())?.as_ptr(),
            to_cstring(fs_type.as_bytes())?.as_ptr(),
            flags,
            match &data_cstr {
                Some(s) => s.as_ptr() as *const c_void,
                None => null(),
            },
        )
    };
    if res == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

pub fn change_propagation<P: AsRef<Path>>(path: P, flags: c_ulong) -> Result<()> {
    mount("none", path, "none", flags, None)
}

pub fn bind_mount_opt<S: AsRef<Path>, T: AsRef<Path>>(
    source: S,
    target: T,
    flags: c_ulong,
) -> Result<()> {
    mount(source, target, "none", flags | MS_BIND, None)
}

pub fn bind_mount<S: AsRef<Path>, T: AsRef<Path>>(source: S, target: T) -> Result<()> {
    bind_mount_opt(source, target, 0)
}

pub fn umount_opt<P: AsRef<Path>>(path: P, flags: c_int) -> Result<()> {
    let res = unsafe {
        libc::umount2(
            to_cstring(path.as_ref().as_os_str().as_bytes())?.as_ptr(),
            flags,
        )
    };
    if res == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

pub fn umount<P: AsRef<Path>>(path: P) -> Result<()> {
    umount_opt(path, 0)
}

pub fn remount_readonly<P: AsRef<Path>>(path: P) -> Result<()> {
    // If a filesystem was mounted with NOSUID/NODEV/NOEXEC, we won't be able to remount the
    // bind-mount without specifying those same flags. Parsing mountinfo seems slow, and this case
    // isn't going to be triggered often in production anyway, so we just use the shotgun approach
    // for now, bruteforcing the flags in the order of most likeliness.
    let mut result = Ok(());
    for flags in [
        0,
        MS_NOSUID,
        MS_NODEV,
        MS_NOSUID | MS_NODEV,
        MS_NOEXEC,
        MS_NOEXEC | MS_NOSUID,
        MS_NOEXEC | MS_NODEV,
        MS_NOEXEC | MS_NOSUID | MS_NODEV,
    ] {
        result = bind_mount_opt("none", path.as_ref(), MS_REMOUNT | MS_RDONLY | flags);
        if let Err(ref e) = result {
            if let ErrorKind::PermissionDenied = e.kind() {
                continue;
            }
        }
        break;
    }
    result
}

pub fn make_memfd(name: &str, contents: &[u8]) -> Result<std::fs::File> {
    let mut file = unsafe {
        std::fs::File::from_raw_fd(memfd::memfd_create(
            &CString::new(name)?,
            memfd::MemFdCreateFlag::MFD_CLOEXEC,
        )?)
    };
    file.write_all(contents)?;
    Ok(file)
}
