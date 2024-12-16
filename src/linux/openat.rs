use rustix::fs::{Dir, Mode, OFlags};
use rustix::io::Result;
use std::fs::File;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};

#[derive(crossmist::Object)]
pub struct OpenAtDir(OwnedFd);

impl OpenAtDir {
    pub fn open<P: rustix::path::Arg>(path: P) -> Result<Self> {
        Ok(Self(rustix::fs::open(
            path,
            OFlags::PATH | OFlags::CLOEXEC,
            Mode::empty(),
        )?))
    }

    pub fn try_clone(&self) -> Result<Self> {
        // Built-in try_clone erroneously does not set CLOEXEC
        Ok(Self(rustix::io::fcntl_dupfd_cloexec(self, 0)?))
    }

    pub fn sub_dir<P: rustix::path::Arg>(&self, path: P) -> Result<Self> {
        Ok(Self(rustix::fs::openat(
            self,
            path,
            OFlags::PATH | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )?))
    }

    pub fn write_file<P: rustix::path::Arg, M: Into<Mode>>(
        &self,
        path: P,
        mode: M,
    ) -> Result<File> {
        Ok(rustix::fs::openat(
            self,
            path,
            OFlags::CREATE | OFlags::TRUNC | OFlags::WRONLY,
            mode.into(),
        )?
        .into())
    }

    pub fn open_file<P: rustix::path::Arg>(&self, path: P) -> Result<File> {
        Ok(rustix::fs::openat(self, path, OFlags::RDONLY, Mode::empty())?.into())
    }

    pub fn create_dir<P: rustix::path::Arg, M: Into<Mode>>(&self, path: P, mode: M) -> Result<()> {
        rustix::fs::mkdirat(self, path, mode.into())
    }

    pub fn list_dir<P: rustix::path::Arg>(&self, path: P) -> Result<Dir> {
        Dir::new(rustix::fs::openat(
            self,
            path,
            OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )?)
    }
}

impl AsFd for OpenAtDir {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.0.as_fd()
    }
}
