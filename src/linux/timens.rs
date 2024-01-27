use crate::log;
use anyhow::{Context, Result};
use nix::{libc, sched, sys::sysinfo, time::ClockId};
use std::fs::File;
use std::io::{Seek, Write};

pub struct TimeNsController {
    timens_offsets: File,
    arch_dependent: TimeNsControllerArchDependent,
    uptime_shift: u64,
}

impl TimeNsController {
    pub fn new() -> Result<Self> {
        let timens_offsets = File::create("/oldroot/proc/self/timens_offsets")
            .context("Failed to open /oldroot/proc/self/timens_offsets for writing")?;
        Ok(Self {
            timens_offsets,
            arch_dependent: TimeNsControllerArchDependent::new()?,
            uptime_shift: 0,
        })
    }

    pub fn get_uptime_shift(&self) -> u64 {
        self.uptime_shift
    }

    pub fn reset_system_time_for_children(&mut self) -> Result<()> {
        log!("Rewinding clocks");

        self.uptime_shift = sysinfo::sysinfo()
            .context("Failed to get sysinfo")?
            .uptime()
            .as_secs();

        // timens_offsets can only be set if no process has entered the timens before
        sched::unshare(sched::CloneFlags::from_bits_retain(libc::CLONE_NEWTIME))
            .context("Failed to unshare timens")?;

        // CLOCK_MONOTONIC is similar to CLOCK_MONOTONIC_RAW: both are monotonic, i.e. NTP doesn't
        // adjust their absolute value, but NTP still adjust the *rate* of the former. Meaning that,
        // in short run, they are offset by a constant value, and we don't know which one is larger.
        // We want to avoid negative times (should not be a problem with sane programs, but not all
        // of them are), so choose the offset so that all the clocks are positive but stay
        // approximately fixed across runs.
        let monotonic_offset = -[
            ClockId::CLOCK_MONOTONIC,
            ClockId::CLOCK_MONOTONIC_RAW,
            ClockId::CLOCK_MONOTONIC_COARSE,
        ]
        .map(|clock_id| clock_id.now().context("Failed to get monotonic time"))
        .into_iter()
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .min()
        .unwrap();

        let boottime_offset = -ClockId::CLOCK_BOOTTIME
            .now()
            .context("Failed to get time since boot")?;

        self.timens_offsets
            .rewind()
            .context("Failed to rewind /oldroot/proc/self/timens_offsets")?;
        self.timens_offsets
            .write_all(
                format!(
                    "monotonic {} {}\nboottime {} {}\n",
                    monotonic_offset.tv_sec(),
                    monotonic_offset.tv_nsec(),
                    boottime_offset.tv_sec(),
                    boottime_offset.tv_nsec()
                )
                .as_ref(),
            )
            .context("Failed to adjust timens offset")?;

        self.arch_dependent.reset_system_time_for_children()?;

        Ok(())
    }
}

#[cfg(target_arch = "x86_64")]
pub fn disable_native_instructions() -> Result<()> {
    // TSC is (who would guess?) monotonic
    if unsafe { libc::prctl(libc::PR_SET_TSC, libc::PR_TSC_SIGSEGV) } != 0 {
        Err(std::io::Error::last_os_error()).context("prctl(PR_SET_TSC) failed")?;
    }
    Ok(())
}

#[cfg(target_arch = "aarch64")]
pub fn disable_native_instructions() -> Result<()> {
    Ok(())
}

#[cfg(target_arch = "x86_64")]
struct TimeNsControllerArchDependent;

#[cfg(target_arch = "x86_64")]
impl TimeNsControllerArchDependent {
    pub fn new() -> Result<Self> {
        Ok(Self)
    }

    pub fn reset_system_time_for_children(&mut self) -> Result<()> {
        Ok(())
    }
}

#[cfg(target_arch = "aarch64")]
struct TimeNsControllerArchDependent {
    kmodule_timing: File,
}

#[cfg(target_arch = "aarch64")]
impl TimeNsControllerArchDependent {
    pub fn new() -> Result<Self> {
        let kmodule_timing = File::create("/oldroot/sys/kernel/sunwalker/timing")
            .context("Failed to open /oldroot/sys/kernel/sunwalker/timing for writing")?;
        Ok(Self { kmodule_timing })
    }

    pub fn reset_system_time_for_children(&mut self) -> Result<()> {
        self.kmodule_timing
            .rewind()
            .context("Failed to rewind /oldroot/sys/kernel/sunwalker/timing")?;

        let mut cntvct_offset: u64;
        unsafe {
            std::arch::asm!(
                "isb",
                "mrs {cntvct_offset}, CNTVCT_EL0",
                cntvct_offset = out(reg) cntvct_offset
            );
        }
        cntvct_offset = 0 - cntvct_offset;

        self.kmodule_timing
            .write_all(format!("{} {}\n", std::process::id(), cntvct_offset).as_ref())
            .context("Failed to adjust CPU timers offset")?;

        Ok(())
    }
}
