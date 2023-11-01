use crate::{util::format_proc_path, entry::START_INFORMATION, libc, anyhow::Result};

pub fn in_master() -> Result<()> {
    Ok(())

    // let fd = format_proc_path(Some(unsafe { START_INFORMATION.orig_pid }), "/fd");

    // libc::getdents64()

    //     for orig_fd in self.orig.list_fds()? {
    //     if orig_fd < 3 {
    //         continue;
    //     }

    //     let fd_info = self.orig.get_fd_info(orig_fd)?;

    //     let slave_fd;

    //     if let Some(count) = fd_info.get("eventfd-count") {
    //         // Clone an eventfd
    //         let count: u32 = count.parse().context("'eventfd-count' is not a number")?;
    //         let mut flags = i32::from_str_radix(
    //             fd_info
    //                 .get("flags")
    //                 .context("'flags' missing from an eventfd fdinfo")?,
    //             16,
    //         )
    //         .context("'flags' is not a hexadecimal number")?;
    //         flags &= !libc::O_ACCMODE;
    //         // FIXME: move this to after fork
    //         slave_fd = self.slave_syscall((libc::SYS_eventfd, count, flags))? as RawFd;
    //     } else {
    //         // Clone a normal fd
    //         let fd = system::pidfd_getfd(orig_pidfd.as_raw_fd(), orig_fd)?;
    //         slave_fd = self.slave_syscall((
    //             libc::SYS_pidfd_getfd,
    //             SUSPENDER_PIDFD_FIXED_FD,
    //             fd.as_raw_fd(),
    //             0,
    //         ))? as RawFd;
    //         // FIXME: this should open another file description
    //     }

    //     // Make the two fds match
    //     ensure!(slave_fd <= orig_fd, "Unexpected allocated fd");
    //     if slave_fd < orig_fd {
    //         self.slave_syscall((libc::SYS_dup2, slave_fd, orig_fd))?;
    //         self.slave_syscall((libc::SYS_close, slave_fd))?;
    //     }

    //     eprintln!("{orig_fd} {slave_fd}");
    // }

    // Ok(())
}
