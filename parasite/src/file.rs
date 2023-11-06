use crate::{anyhow::Result, fixed_vec::FixedVec, libc};
use core::ffi::CStr;

pub struct File {
    fd: i32,
}

pub struct BufReader<'a, const N: usize> {
    file: &'a mut File,
    buffer: FixedVec<u8, N>,
}

pub struct LineIterator<'a, const N: usize> {
    reader: &'a mut BufReader<'a, N>,
    ignore_line: bool,
}

impl File {
    pub fn open(path: &CStr) -> Result<Self> {
        let fd = libc::open(path, libc::O_RDONLY | libc::O_CLOEXEC)? as i32;
        Ok(Self { fd })
    }

    pub fn as_raw_fd(&self) -> i32 {
        self.fd
    }

    pub fn read_into<const N: usize>(&self, buf: &mut FixedVec<u8, N>) -> Result<()> {
        let n_read = libc::read(self.fd, buf.as_mut_ptr(), buf.capacity())?;
        unsafe {
            buf.set_len(n_read as usize);
        }
        Ok(())
    }
}

impl<'a, const N: usize> BufReader<'a, N> {
    pub fn new(file: &'a mut File) -> Self {
        BufReader {
            file,
            buffer: FixedVec::new(),
        }
    }

    pub fn lines(&'a mut self) -> LineIterator<'a, N> {
        LineIterator {
            reader: self,
            ignore_line: false,
        }
    }
}

impl<'a, const N: usize> Iterator for LineIterator<'a, N> {
    type Item = Result<FixedVec<u8, N>>;
    fn next(&mut self) -> Option<Self::Item> {
        'restart: loop {
            let mut offset = 0;
            while offset < self.reader.buffer.capacity() {
                if offset == self.reader.buffer.len() {
                    let result = libc::read(
                        self.reader.file.fd,
                        self.reader.buffer.as_mut_ptr_range().end,
                        self.reader.buffer.capacity() - self.reader.buffer.len(),
                    );
                    match result {
                        Ok(0) => return None,
                        Ok(n_read) => unsafe {
                            self.reader
                                .buffer
                                .set_len(self.reader.buffer.len() + n_read as usize);
                        },
                        Err(error) => return Some(Err(error)),
                    }
                }
                if unsafe { *self.reader.buffer.get_unchecked(offset) } == b'\n' {
                    let line = FixedVec::from(unsafe {
                        self.reader.buffer.slice_unchecked(0..offset + 1)
                    });
                    unsafe {
                        core::ptr::copy(
                            self.reader.buffer.as_ptr().wrapping_add(offset + 1),
                            self.reader.buffer.as_mut_ptr(),
                            self.reader.buffer.len() - (offset + 1),
                        );
                    }
                    unsafe {
                        self.reader
                            .buffer
                            .set_len(self.reader.buffer.len() - (offset + 1));
                    }
                    if self.ignore_line {
                        self.ignore_line = false;
                        continue 'restart;
                    }
                    return Some(Ok(line));
                }
                offset += 1;
            }
            // Emit a cut string
            let line = core::mem::replace(&mut self.reader.buffer, FixedVec::new());
            if self.ignore_line {
                continue 'restart;
            }
            self.ignore_line = true;
            return Some(Ok(line));
        }
    }
}

impl Drop for File {
    fn drop(&mut self) {
        let _ = libc::close(self.fd);
    }
}
