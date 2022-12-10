use anyhow::{Context, Result};
use nix::{libc, libc::c_int, time::ClockId};
use std::fs::File;
use std::io::{Seek, Write};

const CLONE_NEWTIME: c_int = 0x80;

pub struct TimeNsController {
    timens_offsets: File,
}

impl TimeNsController {
    pub fn new() -> Result<Self> {
        let timens_offsets = File::create("/newroot/proc/self/timens_offsets")
            .context("Failed to open /newroot/proc/self/timens_offsets for writing")?;
        Ok(Self { timens_offsets })
    }

    pub fn reset_system_time_for_children(&mut self) -> Result<()> {
        if unsafe { libc::unshare(CLONE_NEWTIME) } != 0 {
            return Err(std::io::Error::last_os_error()).context("unshare() failed");
        }

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
            .context("Failed to rewind /newroot/proc/self/timens_offsets")?;
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

        Ok(())
    }
}
