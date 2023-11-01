use crate::{bail, ensure, anyhow::Result};
use core::ops::{Add, Mul};
use crate::fixed_vec::FixedVec;

#[macro_export]
macro_rules! c {
    ($s:literal) => {
        unsafe { core::ffi::CStr::from_bytes_with_nul_unchecked(concat!($s, "\0").as_bytes()) }
    };
}

pub fn format_proc_path<const N: usize>(pid: Option<i32>, suffix: &[u8; N]) -> FixedVec<u8, {6 + 10 + N + 1}> {
    let Some(pid) = pid else {
        let mut buffer = FixedVec::from(b"/proc/self");
        unsafe {
            buffer.extend_unchecked(suffix);
            buffer.push_unchecked(b'\0');
        }
        return buffer;
    };

    let mut pid = pid as u32;
    let mut buffer = FixedVec::from(b"/proc/");
    unsafe {
        let mut trial = 10;
        let mut pid_length = 1;
        while pid >= trial {
            trial *= 10;
            pid_length += 1;
        }
        for i in (0..pid_length).rev() {
            let offset = buffer.len() + i;
            buffer.write_unchecked(offset, b'0' + (pid % 10) as u8);
            pid /= 10;
        }
        buffer.set_len(buffer.len() + pid_length);

        buffer.extend_unchecked(suffix);
        buffer.push_unchecked(b'\0');
    }
    buffer
}

fn parse_digit(symbol: u8, radix: u8) -> Result<u8> {
    let number;
    if (b'0'..=b'9').contains(&symbol) {
        number = symbol - b'0';
    } else if (b'a'..=b'z').contains(&symbol) {
        number = symbol - b'a' + 10;
    } else {
        bail!("Invalid number");
    }
    ensure!(number < radix, "Invalid number");
    Ok(number)
}

pub fn from_str_radix<T: From<u8> + Add<Output = T> + Mul<Output = T>>(number: &[u8], radix: u8) -> Result<T> {
    let mut result = T::from(0);
    for &symbol in number {
        result = result * T::from(radix) + T::from(parse_digit(symbol, radix)?);
    }
    Ok(result)
}
