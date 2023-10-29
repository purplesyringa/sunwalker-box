use crate::{libc, SyscallResult};
use core::ffi::CStr;
use core::mem::MaybeUninit;
use core::ops::Range;

pub struct File {
    fd: isize,
}

pub struct BufReader<'a> {
    file: &'a mut File,
    buffer: FixedVec,
}

pub struct LineIterator<'a> {
    reader: &'a mut BufReader<'a>,
}

pub struct FixedVec {
    data: [MaybeUninit<u8>; 4096],
    length: usize,
}

impl File {
    pub fn open(path: &CStr) -> Result<Self, SyscallResult> {
        let fd = libc::open(path, libc::O_RDONLY | libc::O_CLOEXEC)?;
        Ok(Self { fd })
    }
}

impl<'a> BufReader<'a> {
    pub fn new(file: &'a mut File) -> Self {
        BufReader {
            file,
            buffer: FixedVec::new(),
        }
    }

    pub fn lines(&'a mut self) -> LineIterator<'a> {
        LineIterator { reader: self }
    }
}

impl FixedVec {
    fn new() -> Self {
        Self {
            data: MaybeUninit::uninit_array(),
            length: 0,
        }
    }

    fn from(src: &[u8]) -> Self {
        let mut vec = Self::new();
        MaybeUninit::write_slice(&mut vec.data[..src.len()], src);
        vec.length = src.len();
        vec
    }

    pub fn len(&self) -> usize {
        self.length
    }

    fn capacity(&self) -> usize {
        self.data.len()
    }

    unsafe fn get_unchecked(&self, index: usize) -> u8 {
        *self.data[index].assume_init_ref()
    }

    unsafe fn slice_unchecked(&self, index: Range<usize>) -> &[u8] {
        MaybeUninit::slice_assume_init_ref(self.data.get_unchecked(index))
    }
}

impl AsRef<[u8]> for FixedVec {
    fn as_ref(&self) -> &[u8] {
        unsafe { self.slice_unchecked(0..self.len()) }
    }
}

impl<'a> Iterator for LineIterator<'a> {
    type Item = Result<FixedVec, SyscallResult>;
    fn next(&mut self) -> Option<Self::Item> {
        let mut offset = 0;
        while offset < self.reader.buffer.capacity() {
            if offset == self.reader.buffer.len() {
                let result = libc::read(
                    self.reader.file.fd,
                    &self.reader.buffer.data[self.reader.buffer.len()],
                    self.reader.buffer.capacity() - self.reader.buffer.len(),
                );
                if result.is_err() {
                    return Some(Err(result));
                } else if result.0 == 0 {
                    return None;
                } else {
                    self.reader.buffer.length += result.0 as usize;
                }
            }
            if unsafe { self.reader.buffer.get_unchecked(offset) } == b'\n' {
                let line =
                    FixedVec::from(unsafe { self.reader.buffer.slice_unchecked(0..offset + 1) });
                unsafe {
                    core::ptr::copy(
                        self.reader.buffer.data.as_ptr().wrapping_add(offset + 1),
                        self.reader.buffer.data.as_mut_ptr(),
                        self.reader.buffer.len() - (offset + 1),
                    );
                }
                self.reader.buffer.length -= offset + 1;
                return Some(Ok(line));
            }
            offset += 1;
        }
        Some(Err(SyscallResult(-libc::ENOMEM)))
    }
}

impl Drop for File {
    fn drop(&mut self) {
        let _ = libc::close(self.fd);
    }
}
