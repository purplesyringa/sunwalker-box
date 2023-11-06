use crate::fixed_vec::FixedVec;

pub unsafe trait Format {
    const ESTIMATED_LENGTH: usize;
    unsafe fn format_to<const N: usize>(&self, vec: &mut FixedVec<u8, N>);
}

pub struct Cons<T, U>(pub T, pub U);
unsafe impl<T: Format, U: Format> Format for Cons<T, U> {
    const ESTIMATED_LENGTH: usize = T::ESTIMATED_LENGTH + U::ESTIMATED_LENGTH;
    unsafe fn format_to<const N: usize>(&self, vec: &mut FixedVec<u8, N>) {
        self.0.format_to(vec);
        self.1.format_to(vec);
    }
}

pub enum Either<T, U> {
    Left(T),
    Right(U),
}
unsafe impl<T: Format, U: Format> Format for Either<T, U> {
    const ESTIMATED_LENGTH: usize = if T::ESTIMATED_LENGTH > U::ESTIMATED_LENGTH {
        T::ESTIMATED_LENGTH
    } else {
        U::ESTIMATED_LENGTH
    };
    unsafe fn format_to<const N: usize>(&self, vec: &mut FixedVec<u8, N>) {
        match self {
            Self::Left(value) => value.format_to(vec),
            Self::Right(value) => value.format_to(vec),
        }
    }
}

pub struct Empty;
unsafe impl Format for Empty {
    const ESTIMATED_LENGTH: usize = 0;
    unsafe fn format_to<const N: usize>(&self, _vec: &mut FixedVec<u8, N>) {}
}

unsafe impl<T: Format> Format for &T {
    const ESTIMATED_LENGTH: usize = T::ESTIMATED_LENGTH;
    unsafe fn format_to<const N: usize>(&self, vec: &mut FixedVec<u8, N>) {
        (*self).format_to(vec)
    }
}

unsafe impl<const M: usize> Format for [u8; M] {
    const ESTIMATED_LENGTH: usize = M;
    unsafe fn format_to<const N: usize>(&self, vec: &mut FixedVec<u8, N>) {
        vec.extend_unchecked(self);
    }
}

pub struct LengthLimitedArg<T, const M: usize>(pub T);
unsafe impl<const M: usize> Format for LengthLimitedArg<&[u8], M> {
    const ESTIMATED_LENGTH: usize = M;
    unsafe fn format_to<const N: usize>(&self, vec: &mut FixedVec<u8, N>) {
        vec.extend_unchecked(self.0);
    }
}

fn get_integer_length(number: u64, radix: u64) -> usize {
    let mut length = 1;
    let mut trial = radix;
    while number >= trial {
        length += 1;
        let (new_trial, overflow) = trial.overflowing_mul(radix);
        if overflow {
            break;
        }
        trial = new_trial;
    }
    length
}

unsafe fn format_integer_to<const N: usize>(
    mut number: u64,
    radix: u64,
    vec: &mut FixedVec<u8, N>,
) {
    let length = get_integer_length(number, radix);
    for i in (0..length).rev() {
        let offset = vec.len() + i;
        let digit: u8 = unsafe { (number % radix).try_into().unwrap_unchecked() };
        let symbol = if radix <= 10 || digit < 10 {
            b'0' + digit
        } else {
            b'a' + (digit - 10)
        };
        unsafe {
            vec.write_unchecked(offset, symbol);
        }
        number /= radix;
    }
    unsafe {
        vec.set_len(vec.len() + length);
    }
}

macro_rules! impl_format_integer {
    ($ty:ty, $decimal_length:literal) => {
        unsafe impl Format for $ty {
            const ESTIMATED_LENGTH: usize = $decimal_length;
            unsafe fn format_to<const N: usize>(&self, vec: &mut FixedVec<u8, N>) {
                format_integer_to(*self as u64, 10, vec)
            }
        }
    };
}

impl_format_integer!(u8, 3);
impl_format_integer!(u16, 5);
impl_format_integer!(u32, 10);
impl_format_integer!(u64, 20);

pub fn format<Arg: Format>(arg: Arg) -> FixedVec<u8, { Arg::ESTIMATED_LENGTH }>
where
    [(); Arg::ESTIMATED_LENGTH]:,
{
    let mut formatted = FixedVec::new();
    unsafe {
        arg.format_to(&mut formatted);
    }
    formatted
}

#[macro_export]
macro_rules! format {
    ($($args:tt)*) => {
        crate::format::format(crate::formatter!($($args)*,))
    };
}

#[macro_export]
macro_rules! formatter {
    ({ <= $max_length:literal } $arg:expr, $($rest:tt)*) => {
        crate::format::Cons(
            crate::format::LengthLimitedArg::<_, $max_length>($arg),
            crate::formatter!($($rest)*),
        )
    };
    ({ either } $arg:expr, $($rest:tt)*) => {
        crate::format::Cons(
            {
                use crate::format::Either::{Left, Right};
                $arg
            },
            crate::formatter!($($rest)*),
        )
    };
    ($arg:expr, $($rest:tt)*) => {
        crate::format::Cons($arg, crate::formatter!($($rest)*))
    };
    ($(,)?) => {
        crate::format::Empty
    };
}
