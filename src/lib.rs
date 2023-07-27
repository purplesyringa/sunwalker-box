#![feature(
    file_create_new,
    io_error_more,
    never_type,
    try_blocks,
    unwrap_infallible
)]

pub mod entry;

#[cfg(target_os = "linux")]
mod linux {
    mod cgroups;
    mod controller;
    pub mod entry;
    mod ids;
    mod ipc;
    mod kmodule;
    mod manager;
    mod mountns;
    mod openat;
    mod procs;
    mod reaper;
    mod rootfs;
    mod running;
    mod sandbox;
    mod system;
    mod timens;
    mod tracing;
    mod userns;
}
