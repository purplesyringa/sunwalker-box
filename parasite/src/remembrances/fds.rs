use crate::{
    anyhow::{Context, Error, Result},
    bail,
    entry::START_INFORMATION,
    file,
    fixed_vec::FixedVec,
    format, libc,
    util::{from_str_radix, split_once},
};
use core::ffi::CStr;

#[repr(C)]
struct linux_dirent64 {
    d_ino: u64,
    d_off: u64,
    d_reclen: u16,
    d_type: u8,
    d_name: [i8],
}

pub struct SavedFd {
    orig_fd: u32,
    flags: u32,
    info: SavedFdInfo,
}

enum SavedFdInfo {
    Regular { master_fd: u32, position: u64 },
    EventFd { count: u32 },
}

pub fn in_master() -> Result<FixedVec<SavedFd, 1024>> {
    let mut saved_fds: FixedVec<SavedFd, 1024> = FixedVec::new();
    let mut first_free_fd = 0;

    for_each_fd(unsafe { START_INFORMATION.orig_pid }, |orig_fd| {
        if orig_fd < 3 {
            return Ok(());
        }

        let mut pos: Option<u64> = None;
        let mut flags: Option<u32> = None;
        let mut eventfd_count = None;

        for_each_fdinfo(
            unsafe { START_INFORMATION.orig_pid },
            orig_fd,
            |key, value| {
                if key == b"pos" {
                    pos = Some(from_str_radix(value, 10).context("'pos' is not a number")?);
                } else if key == b"flags" {
                    flags = Some(
                        from_str_radix(value, 16).context("'flags' is not a hexadecimal number")?,
                    );
                } else if key == b"eventfd-count" {
                    eventfd_count =
                        Some(from_str_radix(value, 10).context("'eventfd-count' is not a number")?);
                }
                Ok(())
            },
        )?;

        let flags = flags.context("'flags' missing")?;

        let info = if let Some(count) = eventfd_count {
            SavedFdInfo::EventFd { count }
        } else {
            SavedFdInfo::Regular {
                master_fd: 0,
                position: pos.context("'pos' missing on regular fd")?,
            }
        };

        saved_fds
            .try_push(SavedFd {
                orig_fd,
                flags,
                info,
            })
            .map_err(|_| Error::custom(libc::EMFILE, "Too many open file descriptors to clone"))?;
        first_free_fd = first_free_fd.max(orig_fd + 1);

        Ok(())
    })?;

    // Open regular fds. At this moment, only fds 0-2 (stdio) are taken, which means we have the
    // guarantee that master_fd <= orig_fd
    for saved_fd in saved_fds.as_mut() {
        match saved_fd.info {
            SavedFdInfo::Regular {
                ref mut master_fd, ..
            } => {
                let path = format!(
                    b"/proc/",
                    unsafe { START_INFORMATION.orig_pid },
                    b"/fd/",
                    saved_fd.orig_fd,
                    b"\0",
                );
                *master_fd = libc::open(path.as_ref(), saved_fd.flags)? as u32;
            }
            _ => {}
        }
    }

    Ok(saved_fds)
}

pub fn in_fork(saved_fds: FixedVec<SavedFd, 1024>) -> Result<()> {
    // As master_fd <= orig_fd and master_fd is increasing, it is safe to dup2 to orig_fd from
    // higher fd to lower fd
    for saved_fd in saved_fds.iter().rev() {
        let fd;
        match saved_fd.info {
            SavedFdInfo::Regular {
                master_fd,
                position,
            } => {
                let path = format!(b"/proc/self/fd/", master_fd, b"\0");
                fd = libc::open(path.as_ref(), saved_fd.flags)? as u32;
                libc::lseek(fd, position, libc::SEEK_SET)?;
            }
            SavedFdInfo::EventFd { count } => {
                fd = libc::eventfd(count, saved_fd.flags & !(libc::O_ACCMODE as u32))? as u32;
            }
        }

        if fd != saved_fd.orig_fd {
            let dupfd = libc::fcntl(
                fd,
                if saved_fd.flags & (libc::O_CLOEXEC as u32) == 0 {
                    libc::F_DUPFD
                } else {
                    libc::F_DUPFD_CLOEXEC
                },
                saved_fd.orig_fd,
            )? as u32;
            if dupfd != saved_fd.orig_fd {
                bail!("fd is unexpectedly taken");
            }
            libc::close(fd)?;
        }
    }
    Ok(())
}

fn for_each_fd(pid: u32, mut handler: impl FnMut(u32) -> Result<()>) -> Result<()> {
    let fd_dir = format!(b"/proc/", pid, b"/fd\0");
    let fd_dir = libc::open(fd_dir.as_ref(), libc::O_CLOEXEC | libc::O_DIRECTORY)?;

    let mut buffer: FixedVec<u8, 1024> = FixedVec::new();
    loop {
        let capacity = buffer.capacity();
        let new_size = libc::getdents64(fd_dir, &mut buffer, capacity)? as usize;
        unsafe {
            buffer.set_len(new_size);
        }
        if buffer.is_empty() {
            break;
        }

        let mut offset = 0;
        while offset < buffer.len() {
            let dent: &linux_dirent64 =
                unsafe { core::mem::transmute(buffer.slice_mut_unchecked(offset..buffer.len())) };
            let name = unsafe { CStr::from_ptr(dent.d_name.as_ptr()) }.to_bytes();
            if unsafe { *name.get_unchecked(0) } != b'.' {
                let fd = from_str_radix(name, 10).context("Invalid fd")?;
                handler(fd)?;
            }
            offset += dent.d_reclen as usize;
        }
    }

    libc::close(fd_dir)?;

    Ok(())
}

fn for_each_fdinfo(
    pid: u32,
    fd: u32,
    mut handler: impl FnMut(&[u8], &[u8]) -> Result<()>,
) -> Result<()> {
    let path = format!(b"/proc/", pid, b"/fdinfo/", fd, b"\0");
    let path = unsafe { CStr::from_bytes_with_nul_unchecked(&path) };
    let mut file = file::File::open(path)?;
    let mut buf: file::BufReader<'_, 128> = file::BufReader::new(&mut file);
    for line in buf.lines() {
        let line = line?;
        if let Some((key, value)) = split_once(&line, b':') {
            handler(key, value.trim_ascii())?;
        }
    }

    Ok(())
}
