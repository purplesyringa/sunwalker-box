use crate::{libc, main};
use core::panic::PanicInfo;

#[panic_handler]
fn panic(_panic: &PanicInfo<'_>) -> ! {
    core::intrinsics::abort();
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    let result = main();
    let _ = libc::exit_group(if result.is_err() { -result.0 } else { 0 });
    core::intrinsics::abort();
}
