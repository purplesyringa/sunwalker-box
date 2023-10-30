#![feature(
    concat_bytes,
    core_intrinsics,
    error_in_core,
    fn_traits,
    maybe_uninit_slice,
    maybe_uninit_uninit_array,
    maybe_uninit_write_slice,
    never_type,
    slice_index_methods,
    try_trait_v2,
    unboxed_closures
)]
#![no_main]
#![no_std]

mod anyhow;
mod file;
mod fixed_vec;
mod libc;
mod runtime;
mod string_table;
mod syscall_wrapper;

use anyhow::{Context, Result};

fn main() -> Result<()> {
    let mut maps =
        file::File::open(c!("/proc/self/maps")).context("Failed to open /proc/self/maps")?;
    let mut buf = file::BufReader::new(&mut maps);
    for line in buf.lines() {
        let line = line.context("Failed to read /proc/self/maps")?;
        let mut line = line.as_ref();

        let mut split_by = |split_c: u8| -> Result<&str> {
            let pos = line
                .iter()
                .position(|&c| c == split_c)
                .context("Invalid maps format")?;
            let s = &line[..pos];
            line = &line[pos + 1..];
            unsafe {
                Ok(core::str::from_utf8_unchecked(s))
            }
        };

        let base = usize::from_str_radix(split_by(b'-')?, 16).context("Invalid maps format")?;
        let end = usize::from_str_radix(split_by(b' ')?, 16).context("Invalid maps format")?;

        if (base..end).contains(&(main as fn() -> Result<()> as usize))
            || line.ends_with(b" [vsyscall]\n")
            || line.ends_with(b" [stack]\n")
        {
            continue;
        }

        libc::munmap(base, end - base).context("Failed to munmap region")?;
    }

    Ok(())
}
