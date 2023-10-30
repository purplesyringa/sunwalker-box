use crate::anyhow::{from_syscall_result, Result};
use core::arch::asm;

#[macro_export]
macro_rules! c {
    ($s:literal) => {
        unsafe { core::ffi::CStr::from_bytes_with_nul_unchecked(concat!($s, "\0").as_bytes()) }
    };
}

pub struct SyscallWrapper(pub isize);

trait Arg {
    fn into_isize(self) -> isize;
}

macro_rules! impl_primitive {
    ($ty:tt $($rest:tt)*) => {
        impl Arg for $ty {
            fn into_isize(self) -> isize {
                self as isize
            }
        }
        impl_primitive!($($rest)*);
    };
    () => {};
}

impl_primitive!(isize usize i32);

impl<T: ?Sized> Arg for &T {
    fn into_isize(self) -> isize {
        self as *const T as *const () as isize
    }
}

impl<T: ?Sized> Arg for *const T {
    fn into_isize(self) -> isize {
        self as *const () as isize
    }
}

impl<T: ?Sized> Arg for &mut T {
    fn into_isize(self) -> isize {
        self as *const T as *const () as isize
    }
}

impl<T: ?Sized> Arg for *mut T {
    fn into_isize(self) -> isize {
        self as *const () as isize
    }
}

impl FnOnce<()> for SyscallWrapper {
    type Output = Result<isize>;
    extern "rust-call" fn call_once(self, _args: ()) -> Result<isize> {
        let return_value: isize;
        unsafe {
            asm!(
                "syscall",
                in("rax") self.0,
                lateout("rax") return_value,
                lateout("rcx") _,
                lateout("r11") _,
            );
        }
        from_syscall_result(return_value)
    }
}

impl<T1: Arg> FnOnce<(T1,)> for SyscallWrapper {
    type Output = Result<isize>;
    extern "rust-call" fn call_once(self, args: (T1,)) -> Result<isize> {
        let return_value: isize;
        unsafe {
            asm!(
                "syscall",
                in("rax") self.0,
                in("rdi") args.0.into_isize(),
                lateout("rax") return_value,
                lateout("rcx") _,
                lateout("r11") _,
            );
        }
        from_syscall_result(return_value)
    }
}

impl<T1: Arg, T2: Arg> FnOnce<(T1, T2)> for SyscallWrapper {
    type Output = Result<isize>;
    extern "rust-call" fn call_once(self, args: (T1, T2)) -> Result<isize> {
        let return_value: isize;
        unsafe {
            asm!(
                "syscall",
                in("rax") self.0,
                in("rdi") args.0.into_isize(),
                in("rsi") args.1.into_isize(),
                lateout("rax") return_value,
                lateout("rcx") _,
                lateout("r11") _,
            );
        }
        from_syscall_result(return_value)
    }
}

impl<T1: Arg, T2: Arg, T3: Arg> FnOnce<(T1, T2, T3)> for SyscallWrapper {
    type Output = Result<isize>;
    extern "rust-call" fn call_once(self, args: (T1, T2, T3)) -> Result<isize> {
        let return_value: isize;
        unsafe {
            asm!(
                "syscall",
                in("rax") self.0,
                in("rdi") args.0.into_isize(),
                in("rsi") args.1.into_isize(),
                in("rdx") args.2.into_isize(),
                lateout("rax") return_value,
                lateout("rcx") _,
                lateout("r11") _,
            );
        }
        from_syscall_result(return_value)
    }
}

impl<T1: Arg, T2: Arg, T3: Arg, T4: Arg> FnOnce<(T1, T2, T3, T4)> for SyscallWrapper {
    type Output = Result<isize>;
    extern "rust-call" fn call_once(self, args: (T1, T2, T3, T4)) -> Result<isize> {
        let return_value: isize;
        unsafe {
            asm!(
                "syscall",
                in("rax") self.0,
                in("rdi") args.0.into_isize(),
                in("rsi") args.1.into_isize(),
                in("rdx") args.2.into_isize(),
                in("r10") args.3.into_isize(),
                lateout("rax") return_value,
                lateout("rcx") _,
                lateout("r11") _,
            );
        }
        from_syscall_result(return_value)
    }
}

impl<T1: Arg, T2: Arg, T3: Arg, T4: Arg, T5: Arg> FnOnce<(T1, T2, T3, T4, T5)> for SyscallWrapper {
    type Output = Result<isize>;
    extern "rust-call" fn call_once(self, args: (T1, T2, T3, T4, T5)) -> Result<isize> {
        let return_value: isize;
        unsafe {
            asm!(
                "syscall",
                in("rax") self.0,
                in("rdi") args.0.into_isize(),
                in("rsi") args.1.into_isize(),
                in("rdx") args.2.into_isize(),
                in("r10") args.3.into_isize(),
                in("r8") args.4.into_isize(),
                lateout("rax") return_value,
                lateout("rcx") _,
                lateout("r11") _,
            );
        }
        from_syscall_result(return_value)
    }
}

impl<T1: Arg, T2: Arg, T3: Arg, T4: Arg, T5: Arg, T6: Arg> FnOnce<(T1, T2, T3, T4, T5, T6)>
    for SyscallWrapper
{
    type Output = Result<isize>;
    extern "rust-call" fn call_once(self, args: (T1, T2, T3, T4, T5, T6)) -> Result<isize> {
        let return_value: isize;
        unsafe {
            asm!(
                "syscall",
                in("rax") self.0,
                in("rdi") args.0.into_isize(),
                in("rsi") args.1.into_isize(),
                in("rdx") args.2.into_isize(),
                in("r10") args.3.into_isize(),
                in("r8") args.4.into_isize(),
                in("r9") args.5.into_isize(),
                lateout("rax") return_value,
                lateout("rcx") _,
                lateout("r11") _,
            );
        }
        from_syscall_result(return_value)
    }
}
