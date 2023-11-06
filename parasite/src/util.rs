use crate::{anyhow::Result, bail, ensure};
use core::ops::{Add, Mul};

#[macro_export]
macro_rules! c {
    ($s:literal) => {
        unsafe { core::ffi::CStr::from_bytes_with_nul_unchecked(concat!($s, "\0").as_bytes()) }
    };
}

fn parse_digit(symbol: u8, radix: u8) -> Result<u8> {
    let number = if (b'0'..=b'9').contains(&symbol) {
        symbol - b'0'
    } else if (b'a'..=b'z').contains(&symbol) {
        symbol - b'a' + 10
    } else {
        bail!("Invalid number")
    };
    ensure!(number < radix, "Invalid number");
    Ok(number)
}

pub fn from_str_radix<T: From<u8> + Add<Output = T> + Mul<Output = T>>(
    number: &[u8],
    radix: u8,
) -> Result<T> {
    let mut result = T::from(0);
    for &symbol in number {
        result = result * T::from(radix) + T::from(parse_digit(symbol, radix)?);
    }
    Ok(result)
}

pub fn split_once(string: &[u8], symbol: u8) -> Option<(&[u8], &[u8])> {
    let offset = string.iter().position(|&c| c == symbol)?;
    unsafe {
        Some((
            string.get_unchecked(..offset),
            string.get_unchecked(offset + 1..),
        ))
    }
}

pub fn heap_sort<T, Key: Ord>(array: &mut [T], key: impl Fn(&T) -> Key) {
    unsafe {
        let mut start = array.len() / 2;
        let mut end = array.len();
        while end > 1 {
            if start > 0 {
                start -= 1;
            } else {
                end -= 1;
                array.swap_unchecked(end, 0);
            }
            let mut root = start;
            while root * 2 + 1 < end {
                let mut child = root * 2 + 1;
                if child + 1 < end
                    && key(array.get_unchecked(child)) < key(array.get_unchecked(child + 1))
                {
                    child += 1;
                }
                if key(array.get_unchecked(root)) < key(array.get_unchecked(child)) {
                    array.swap_unchecked(root, child);
                    root = child;
                } else {
                    break;
                }
            }
        }
    }
}
