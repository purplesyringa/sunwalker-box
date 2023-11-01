use core::mem::MaybeUninit;
use core::ops::{Deref, DerefMut, Range};

pub struct FixedVec<T, const N: usize> {
    data: [MaybeUninit<T>; N],
    length: usize,
}

impl<T, const N: usize> FixedVec<T, N> {
    pub fn new() -> Self {
        Self {
            data: MaybeUninit::uninit_array(),
            length: 0,
        }
    }

    pub fn from(src: &[T]) -> Self
    where
        T: Clone,
    {
        let mut vec = Self::new();
        MaybeUninit::write_slice_cloned(&mut vec.data[..src.len()], src);
        vec.length = src.len();
        vec
    }

    pub fn len(&self) -> usize {
        self.length
    }
    pub unsafe fn set_len(&mut self, length: usize) {
        self.length = length;
    }

    pub fn capacity(&self) -> usize {
        self.data.len()
    }

    pub unsafe fn get_unchecked(&self, index: usize) -> &T {
        self.data.get_unchecked(index).assume_init_ref()
    }
    pub unsafe fn get_unchecked_mut(&mut self, index: usize) -> &mut T {
        self.data.get_unchecked_mut(index).assume_init_mut()
    }

    pub unsafe fn write_unchecked(&mut self, index: usize, value: T) -> &mut T {
        self.data.get_unchecked_mut(index).write(value)
    }

    pub unsafe fn slice_unchecked(&self, index: Range<usize>) -> &[T] {
        MaybeUninit::slice_assume_init_ref(self.data.get_unchecked(index))
    }
    pub unsafe fn slice_mut_unchecked(&mut self, index: Range<usize>) -> &mut [T] {
        MaybeUninit::slice_assume_init_mut(self.data.get_unchecked_mut(index))
    }

    pub fn as_ptr(&self) -> *const T {
        self.as_ref().as_ptr()
    }
    pub fn as_mut_ptr(&mut self) -> *mut T {
        self.as_mut().as_mut_ptr()
    }

    pub fn as_mut_ptr_range(&mut self) -> Range<*mut T> {
        self.as_mut().as_mut_ptr_range()
    }

    pub unsafe fn extend_unchecked(&mut self, values: &[T])
    where
        T: Clone,
    {
        MaybeUninit::write_slice_cloned(
            self.data
                .get_unchecked_mut(self.length..self.length + values.len()),
            values,
        );
        self.length += values.len();
    }
    pub unsafe fn push_unchecked(&mut self, value: T) {
        self.data.get_unchecked_mut(self.length).write(value);
        self.length += 1;
    }

    pub fn try_push(&mut self, value: T) -> Result<(), T> {
        if self.len() < self.capacity() {
            unsafe { self.push_unchecked(value); }
            Ok(())
        } else {
            Err(value)
        }
    }

    pub unsafe fn last_unchecked(&mut self) -> &mut T {
        self.get_unchecked_mut(self.length - 1)
    }
}

impl<T, const N: usize> AsRef<[T]> for FixedVec<T, N> {
    fn as_ref(&self) -> &[T] {
        unsafe { self.slice_unchecked(0..self.len()) }
    }
}
impl<T, const N: usize> AsMut<[T]> for FixedVec<T, N> {
    fn as_mut(&mut self) -> &mut [T] {
        unsafe { self.slice_mut_unchecked(0..self.len()) }
    }
}

impl<T, const N: usize> Deref for FixedVec<T, N> {
    type Target = [T];
    fn deref(&self) -> &[T] {
        unsafe { self.slice_unchecked(0..self.len()) }
    }
}
impl<T, const N: usize> DerefMut for FixedVec<T, N> {
    fn deref_mut(&mut self) -> &mut [T] {
        unsafe { self.slice_mut_unchecked(0..self.len()) }
    }
}

impl<T: PartialEq, const N: usize> PartialEq for FixedVec<T, N> {
    fn eq(&self, other: &Self) -> bool {
        self.as_ref() == other.as_ref()
    }
}
