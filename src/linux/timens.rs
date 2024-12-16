use crate::log;
use anyhow::{Context, Result};
use rustix::io::Errno;
use rustix::process::TimeStampCounterReadability;
use rustix::thread::UnshareFlags;
use rustix::time::ClockId;
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

        self.uptime_shift = rustix::system::sysinfo().uptime as u64;

        // timens_offsets can only be set if no process has entered the timens before
        unsafe { rustix::thread::unshare_unsafe(UnshareFlags::NEWTIME) }
            .context("Failed to unshare timens")?;

        // CLOCK_MONOTONIC is similar to CLOCK_MONOTONIC_RAW: both are monotonic, i.e. NTP doesn't
        // adjust their absolute value, but NTP still adjust the *rate* of the former. Meaning that,
        // in short run, they are offset by a constant value, and we don't know which one is larger.
        // We want to avoid negative times (should not be a problem with sane programs, but not all
        // of them are), so choose the offset so that all the clocks are positive but stay
        // approximately fixed across runs.
        let monotonic_offset = -*[
            ClockId::Monotonic,
            ClockId::MonotonicRaw,
            ClockId::MonotonicCoarse,
        ]
        .map(rustix::time::clock_gettime)
        .iter()
        .min()
        .unwrap();

        let boottime_offset = -rustix::time::clock_gettime(ClockId::Boottime);

        self.timens_offsets
            .rewind()
            .context("Failed to rewind /oldroot/proc/self/timens_offsets")?;
        self.timens_offsets
            .write_all(
                format!(
                    "monotonic {} {}\nboottime {} {}\n",
                    monotonic_offset.tv_sec,
                    monotonic_offset.tv_nsec,
                    boottime_offset.tv_sec,
                    boottime_offset.tv_nsec
                )
                .as_ref(),
            )
            .context("Failed to adjust timens offset")?;

        self.arch_dependent.reset_system_time_for_children()?;

        Ok(())
    }
}

#[cfg(target_arch = "x86_64")]
pub fn disable_native_instructions() -> Result<(), Errno> {
    // TSC is (who would guess?) monotonic
    // XXX(linux-6.12): Maybe drop kernel module because PR_SET_TSC is implemented for arm64
    rustix::process::set_time_stamp_counter_readability(TimeStampCounterReadability::RaiseSIGSEGV)
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
