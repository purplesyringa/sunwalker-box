#![feature(io_safety)]
#![feature(auto_traits)]
#![feature(negative_impls)]
#![feature(specialization)]
#![feature(unix_socket_ancillary_data)]
#![feature(unboxed_closures)]
#![feature(fn_traits)]
#![feature(ptr_metadata)]
#![feature(never_type)]
#![feature(generic_associated_types)]
#![feature(try_blocks)]
#![feature(unwrap_infallible)]

extern crate self as multiprocessing;

pub use multiprocessing_derive::*;

pub mod imp;

pub mod serde;
pub use crate::serde::*;

pub mod ipc;
pub use ipc::{channel, duplex, Duplex, Receiver, Sender, TransmissibleObject};

pub mod tokio;

pub mod subprocess;
pub use subprocess::*;

pub mod builtins;

pub mod fns;
pub use fns::*;

pub mod delayed;
pub use delayed::Delayed;

pub use nix::libc;
