use crate::{libc, main};
use core::panic::PanicInfo;

#[panic_handler]
fn panic(_panic: &PanicInfo<'_>) -> ! {
    core::intrinsics::abort();
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    let result = main();
    match result {
        Ok(()) => {
            let _ = libc::exit_group(0);
        }
        Err(error) => {
            let _ = error.print_to_stderr();
            let _ = libc::exit_group(error.errno());
        }
    };
    core::intrinsics::abort();
}
