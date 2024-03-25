use std::mem::ManuallyDrop;
use std::ops::{Deref, DerefMut};

#[repr(C)]
pub union ZeroedPadding<T>
where
    [u8; std::mem::size_of::<T>()]:,
{
    init: ManuallyDrop<T>,
    bytes: [u8; std::mem::size_of::<T>()],
}

impl<T> ZeroedPadding<T>
where
    [u8; std::mem::size_of::<T>()]:,
{
    pub unsafe fn zeroed() -> Self {
        Self {
            bytes: [0u8; std::mem::size_of::<T>()],
        }
    }

    pub unsafe fn bytes(&self) -> &[u8] {
        unsafe { &self.bytes }
    }
}

impl<T> Deref for ZeroedPadding<T>
where
    [u8; std::mem::size_of::<T>()]:,
{
    type Target = T;
    fn deref(&self) -> &T {
        unsafe { &self.init }
    }
}

impl<T> DerefMut for ZeroedPadding<T>
where
    [u8; std::mem::size_of::<T>()]:,
{
    fn deref_mut(&mut self) -> &mut T {
        unsafe { &mut self.init }
    }
}

impl<T> Drop for ZeroedPadding<T>
where
    [u8; std::mem::size_of::<T>()]:,
{
    fn drop(&mut self) {
        unsafe { ManuallyDrop::drop(&mut self.init) }
    }
}

#[macro_export]
macro_rules! copy_field_by_field {
    ($target:expr, { $($name:ident: $value:expr),* $(,)? }) => {{
        let target = &mut $target;
        unsafe {
            $(std::ptr::copy_nonoverlapping(&$value, &mut target.$name, 1);)*
        }
    }};
}
