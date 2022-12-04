#![feature(
    io_error_more,
    is_some_and,
    never_type,
    try_blocks,
    unix_chown,
    unwrap_infallible
)]

pub mod entry;

#[cfg(target_os = "linux")]
mod linux {
    mod cgroups;
    mod controller;
    pub mod entry;
    mod ids;
    mod manager;
    mod mountns;
    mod procs;
    mod reaper;
    mod rootfs;
    mod sandbox;
    mod system;
    mod userns;
}
