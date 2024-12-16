use crate::log;
use anyhow::Result;
use rustix::io::Errno;

pub fn install() -> Result<()> {
    let kmodule = include_bytes!("../../target/sunwalker.ko");
    if !kmodule.is_empty() {
        log!("Loading kernel module");
        if let Err(e) = rustix::system::init_module(kmodule, c"")
            && e != Errno::EXIST
        {
            Err(e)?;
        }
    }
    Ok(())
}
