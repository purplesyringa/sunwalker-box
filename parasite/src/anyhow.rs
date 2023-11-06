use crate::fixed_vec::FixedVec;
use crate::libc;
use crate::string_table::errno_to_name;
use crate::types::iovec;

pub trait Context {
    type Target;
    fn context(self, message: &'static str) -> Self::Target;
}

pub struct Error {
    errno: isize,
    context: FixedVec<&'static str, 8>,
}

impl Error {
    pub fn from_errno(errno: isize) -> Self {
        Self {
            errno,
            context: FixedVec::new(),
        }
    }

    pub fn custom(errno: isize, message: &'static str) -> Error {
        Self {
            errno,
            context: FixedVec::from(&[message]),
        }
    }

    pub fn errno(&self) -> isize {
        self.errno
    }

    pub fn print_to_stderr(&self) -> Result<()> {
        let mut iov: FixedVec<iovec, { 8 * 2 + 3 }> = FixedVec::new();
        unsafe {
            match self.errno.try_into().ok().and_then(errno_to_name) {
                Some(name) => {
                    let literal = "Parasite failed with error E";
                    iov.push_unchecked(iovec {
                        iov_base: literal.as_ptr(),
                        iov_len: literal.len(),
                    });
                    iov.push_unchecked(iovec {
                        iov_base: name.as_ptr(),
                        iov_len: name.len(),
                    });
                }
                None => {
                    let literal = "Parasite failed with unknown error";
                    iov.push_unchecked(iovec {
                        iov_base: literal.as_ptr(),
                        iov_len: literal.len(),
                    });
                }
            }
            let literal = ". Traceback (most recent call last):\n";
            iov.push_unchecked(iovec {
                iov_base: literal.as_ptr(),
                iov_len: literal.len(),
            });
            for i in 0..self.context.len() {
                let error = self.context.get_unchecked(i);
                iov.push_unchecked(iovec {
                    iov_base: error.as_ptr(),
                    iov_len: error.len(),
                });
                iov.push_unchecked(iovec {
                    iov_base: b"\n".as_ptr(),
                    iov_len: 1,
                });
            }
        }
        libc::writev(2, iov.as_ref(), iov.len())?;
        Ok(())
    }
}

pub type Result<T> = core::result::Result<T, Error>;

pub fn from_syscall_result(result: isize) -> Result<isize> {
    if (-4095..0).contains(&result) {
        Err(Error::from_errno(-result))
    } else {
        Ok(result)
    }
}

impl Context for Error {
    type Target = Error;
    fn context(mut self, message: &'static str) -> Error {
        if self.context.len() < self.context.capacity() {
            unsafe {
                self.context.push_unchecked(message);
            }
        } else {
            unsafe {
                *self.context.last_unchecked() = "More hidden...";
            }
        }
        self
    }
}

impl<T> Context for Result<T> {
    type Target = Result<T>;
    fn context(self, message: &'static str) -> Result<T> {
        self.map_err(|error| error.context(message))
    }
}

impl<T, E: core::error::Error> Context for core::result::Result<T, E> {
    type Target = Result<T>;
    fn context(self, message: &'static str) -> Result<T> {
        self.map_err(|_| Error::custom(libc::EINVAL, message))
    }
}

impl<T> Context for Option<T> {
    type Target = Result<T>;
    fn context(self, message: &'static str) -> Result<T> {
        self.ok_or(Error::custom(libc::ENOENT, message))
    }
}

#[macro_export]
macro_rules! bail {
    ($description:expr) => {
        return Err(crate::anyhow::Error::custom(
            crate::libc::EINVAL,
            $description,
        ))
    };
}

#[macro_export]
macro_rules! ensure {
    ($expr:expr, $description:expr) => {
        if !$expr {
            crate::bail!($description);
        }
    };
}
