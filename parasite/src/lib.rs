#![feature(
    byte_slice_trim_ascii,
    concat_bytes,
    core_intrinsics,
    error_in_core,
    fn_traits,
    generic_const_exprs,
    maybe_uninit_slice,
    maybe_uninit_uninit_array,
    maybe_uninit_write_slice,
    never_type,
    slice_index_methods,
    slice_swap_unchecked,
    try_trait_v2,
    unboxed_closures
)]
#![no_main]
#![no_std]

mod anyhow;
pub mod entry;
mod file;
mod fixed_vec;
mod format;
mod libc;
mod remembrances;
pub mod runtime;
mod string_table;
mod syscall_wrapper;
mod types;
mod util;
