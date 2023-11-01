use crate::{libc, anyhow::Result};
use core::panic::PanicInfo;

#[panic_handler]
fn panic(_panic: &PanicInfo<'_>) -> ! {
    core::intrinsics::abort();
}

#[no_mangle]
static STACK: [u8; 40960] = [0u8; 40960];

#[no_mangle]
pub fn go(action: fn() -> Result<()>) -> ! {
    let result = action();
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
