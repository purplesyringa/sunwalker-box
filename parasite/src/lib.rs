#![feature(
    concat_bytes,
    core_intrinsics,
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

mod file;
mod libc;
mod runtime;
mod syscall_wrapper;

use syscall_wrapper::SyscallResult;

fn main() -> SyscallResult {
    let mut file = file::File::open(c!("/proc/self/maps"))?;
    let mut buf = file::BufReader::new(&mut file);
    for line in buf.lines() {
        let line = line?;
        libc::write(1, line.as_ref(), line.len())?;
    }
    SyscallResult(0)
}
