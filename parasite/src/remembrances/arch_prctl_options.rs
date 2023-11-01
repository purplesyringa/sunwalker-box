use crate::{libc, anyhow::Result};

const ARCH_SET_GS: i32 = 0x1001;
const ARCH_SET_FS: i32 = 0x1002;
const ARCH_GET_FS: i32 = 0x1003;
const ARCH_GET_GS: i32 = 0x1004;
const ARCH_GET_CPUID: i32 = 0x1011;
const ARCH_SET_CPUID: i32 = 0x1012;

pub struct Options {
    fs_base: usize,
    gs_base: usize,
    cpuid_status: isize,
}

pub fn in_orig() -> Result<Options> {
    let mut options = Options {
        fs_base: 0,
        gs_base: 0,
        cpuid_status: libc::arch_prctl(ARCH_GET_CPUID)?,
    };
    libc::arch_prctl(ARCH_GET_FS, &mut options.fs_base)?;
    libc::arch_prctl(ARCH_GET_GS, &mut options.gs_base)?;
    Ok(options)
}

pub fn in_master(options: Options) -> Result<()> {
    libc::arch_prctl(ARCH_SET_FS, options.fs_base)?;
    libc::arch_prctl(ARCH_SET_GS, options.gs_base)?;
    libc::arch_prctl(ARCH_SET_CPUID, options.cpuid_status)?;
    Ok(())
}
