#![cfg_attr(unix, feature(unix_socket_ancillary_data))]
#![feature(unboxed_closures)]
#![feature(fn_traits)]
#![feature(ptr_metadata)]
#![feature(never_type)]
#![feature(try_blocks)]
#![feature(unwrap_infallible)]

extern crate self as multiprocessing;

pub use multiprocessing_derive::*;

pub mod imp;

pub mod serde;
pub use crate::serde::*;

mod platform {
    #[cfg(unix)]
    pub mod unix {
        pub mod handles;
        pub mod ipc;
        pub mod subprocess;
        pub mod tokio;
    }
    #[cfg(windows)]
    pub mod windows {
        pub mod handles;
        pub mod ipc;
        pub mod subprocess;
        pub mod tokio;
    }
}

#[cfg(unix)]
pub use crate::platform::unix::*;
#[cfg(windows)]
pub use crate::platform::windows::*;

pub use ipc::{channel, duplex, Duplex, Receiver, Sender, TransmissibleObject};

pub use subprocess::*;

pub mod builtins;

pub mod delayed;
pub use delayed::Delayed;

pub mod fns;
pub use fns::*;
