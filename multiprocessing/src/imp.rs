pub use ctor::ctor;

use crate::{
    handles::{FromRawHandle, OwnedHandle, RawHandle},
    Deserializer, FnOnceObject, Receiver,
};
use lazy_static::lazy_static;
use std::sync::RwLock;

lazy_static! {
    pub static ref MAIN_ENTRY: RwLock<Option<fn() -> i32>> = RwLock::new(None);
}

pub trait Report {
    fn report(self) -> i32;
}

impl Report for () {
    fn report(self) -> i32 {
        0
    }
}

impl<T, E: std::fmt::Debug> Report for Result<T, E> {
    fn report(self) -> i32 {
        match self {
            Ok(_) => 0,
            Err(e) => {
                eprintln!("Error: {e:?}");
                1
            }
        }
    }
}

// We use this little trick to implement the 'trivial_bounds' feature in stable Rust. Instead of
// 'where T: Bounds', we use 'where for<'a> Identity<'a, T>: Bounds'. This seems to confuse the
// hell out of rustc and makes it believe the where clause is not trivial. Credits go to
// @danielhenrymantilla at GitHub, see:
// - https://github.com/getditto/safer_ffi/blob/65a8a2d8ccfd5ef5b5f58a495bc8cea9da07c6fc/src/_lib.rs#L519-L534
// - https://github.com/getditto/safer_ffi/blob/64b921bdcabe441b957742332773248af6677a89/src/proc_macro/utils/trait_impl_shenanigans.rs#L6-L28
pub type Identity<'a, T> = <T as IdentityImpl<'a>>::Type;
pub trait IdentityImpl<'a> {
    type Type: ?Sized;
}
impl<T: ?Sized> IdentityImpl<'_> for T {
    type Type = Self;
}

pub fn main() {
    let mut args = std::env::args();
    if let Some(s) = args.next() {
        if s == "_multiprocessing_" {
            multiprocessing_main(args);
        }
    }

    std::process::exit(MAIN_ENTRY
        .read()
        .expect("Failed to acquire read access to MAIN_ENTRY")
        .expect(
            "MAIN_ENTRY was not registered: is #[multiprocessing::main] missing?",
        )());
}

#[cfg(unix)]
fn multiprocessing_main(mut args: std::env::Args) -> ! {
    let handle: RawHandle = parse_raw_handle(
        &args
            .next()
            .expect("Expected one CLI argument for multiprocessing"),
    );

    enable_cloexec(handle).expect("Failed to set O_CLOEXEC for the file descriptor");

    let mut entry_rx = unsafe { Receiver::<(Vec<u8>, Vec<RawHandle>)>::from_raw_handle(handle) };

    let (entry_data, entry_handles) = entry_rx
        .recv()
        .expect("Failed to read entry for multiprocessing")
        .expect("No entry passed");

    std::mem::forget(entry_rx);

    for handle in &entry_handles {
        enable_cloexec(*handle).expect("Failed to set O_CLOEXEC for the file descriptor");
    }

    let entry_handles = entry_handles
        .into_iter()
        .map(|handle| unsafe { OwnedHandle::from_raw_handle(handle) })
        .collect();

    let entry: Box<dyn FnOnceObject<(RawHandle,), Output = i32>> =
        Deserializer::from(entry_data, entry_handles).deserialize();
    std::process::exit(entry(handle))
}

#[cfg(windows)]
fn multiprocessing_main(mut args: std::env::Args) -> ! {
    let handle_tx: RawHandle = parse_raw_handle(
        &args
            .next()
            .expect("Expected two CLI arguments for multiprocessing"),
    );
    let handle_rx: RawHandle = parse_raw_handle(
        &args
            .next()
            .expect("Expected two CLI arguments for multiprocessing"),
    );

    enable_cloexec(handle_tx).expect("Failed to set O_CLOEXEC for the file descriptor");
    enable_cloexec(handle_rx).expect("Failed to set O_CLOEXEC for the file descriptor");

    let mut entry_rx = unsafe { Receiver::<(Vec<u8>, Vec<RawHandle>)>::from_raw_handle(handle_rx) };

    let (entry_data, entry_handles) = entry_rx
        .recv()
        .expect("Failed to read entry for multiprocessing")
        .expect("No entry passed");

    drop(entry_rx);

    for handle in &entry_handles {
        enable_cloexec(*handle).expect("Failed to set O_CLOEXEC for the file descriptor");
    }

    let entry_handles = entry_handles
        .into_iter()
        .map(|handle| unsafe { OwnedHandle::from_raw_handle(handle) })
        .collect();

    let entry: Box<dyn FnOnceObject<(RawHandle,), Output = i32>> =
        Deserializer::from(entry_data, entry_handles).deserialize();
    std::process::exit(entry(handle_tx))
}

#[cfg(unix)]
fn parse_raw_handle(s: &str) -> RawHandle {
    s.parse().expect("Failed to parse fd")
}
#[cfg(windows)]
fn parse_raw_handle(s: &str) -> RawHandle {
    use windows::Win32::Foundation;
    Foundation::HANDLE(s.parse::<isize>().expect("Failed to parse handle"))
}

#[cfg(unix)]
pub fn disable_cloexec(fd: RawHandle) -> std::io::Result<()> {
    nix::fcntl::fcntl(
        fd,
        nix::fcntl::FcntlArg::F_SETFD(nix::fcntl::FdFlag::empty()),
    )?;
    Ok(())
}
#[cfg(unix)]
pub fn enable_cloexec(fd: RawHandle) -> std::io::Result<()> {
    nix::fcntl::fcntl(
        fd,
        nix::fcntl::FcntlArg::F_SETFD(nix::fcntl::FdFlag::FD_CLOEXEC),
    )?;
    Ok(())
}
#[cfg(unix)]
pub fn disable_nonblock(fd: RawHandle) -> std::io::Result<()> {
    nix::fcntl::fcntl(
        fd,
        nix::fcntl::FcntlArg::F_SETFL(nix::fcntl::OFlag::empty()),
    )?;
    Ok(())
}
#[cfg(unix)]
pub fn enable_nonblock(fd: RawHandle) -> std::io::Result<()> {
    nix::fcntl::fcntl(
        fd,
        nix::fcntl::FcntlArg::F_SETFL(nix::fcntl::OFlag::O_NONBLOCK),
    )?;
    Ok(())
}

#[cfg(windows)]
pub fn disable_cloexec(handle: RawHandle) -> std::io::Result<()> {
    use windows::Win32::Foundation;
    unsafe {
        Foundation::SetHandleInformation(
            handle,
            Foundation::HANDLE_FLAG_INHERIT.0,
            Foundation::HANDLE_FLAG_INHERIT,
        )
        .ok()?
    };
    Ok(())
}
#[cfg(windows)]
pub fn enable_cloexec(handle: RawHandle) -> std::io::Result<()> {
    use windows::Win32::Foundation;
    unsafe {
        Foundation::SetHandleInformation(
            handle,
            Foundation::HANDLE_FLAG_INHERIT.0,
            Foundation::HANDLE_FLAGS::default(),
        )
        .ok()?
    };
    Ok(())
}
#[cfg(windows)]
pub fn is_cloexec(handle: RawHandle) -> std::io::Result<bool> {
    use windows::Win32::Foundation;
    let mut flags = 0u32;
    unsafe { Foundation::GetHandleInformation(handle, &mut flags as *mut u32).ok()? };
    Ok((flags & Foundation::HANDLE_FLAG_INHERIT.0) == 0)
}
