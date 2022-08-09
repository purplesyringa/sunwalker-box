use std::os::unix::io;

pub trait FromRawHandle: io::FromRawFd {
    unsafe fn from_raw_handle(handle: RawHandle) -> Self
    where
        Self: Sized,
    {
        Self::from_raw_fd(handle)
    }
}
pub trait IntoRawHandle: io::IntoRawFd {
    fn into_raw_handle(self) -> RawHandle
    where
        Self: Sized,
    {
        self.into_raw_fd()
    }
}
pub trait AsRawHandle: io::AsRawFd {
    fn as_raw_handle(&self) -> RawHandle {
        self.as_raw_fd()
    }
}

impl<T: io::FromRawFd> FromRawHandle for T {}
impl<T: io::IntoRawFd> IntoRawHandle for T {}
impl<T: io::AsRawFd> AsRawHandle for T {}

pub type RawHandle = io::RawFd;
pub type OwnedHandle = io::OwnedFd;
