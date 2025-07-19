use crate::log;
use anyhow::Result;
use nix::{errno::Errno, kmod::init_module};
use std::ffi::CString;

pub fn install() -> Result<()> {
    let kmodule = include_bytes!("../../target/sunwalker.ko");
    if !kmodule.is_empty() {
        log!("Loading kernel module");
        if let Err(e) = init_module(kmodule, &CString::new("").unwrap())
            && e != Errno::EEXIST {
                Err(e)?;
            }
    }
    Ok(())
}
