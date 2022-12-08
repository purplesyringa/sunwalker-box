use crate::linux::system;
use anyhow::{Context, Result};
use nix::{libc, libc::CLONE_NEWPID};
use std::path::PathBuf;

pub fn unshare_pidns() -> std::io::Result<()> {
    if unsafe { libc::unshare(CLONE_NEWPID) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

pub fn mount_procfs(proc_path: &str) -> Result<()> {
    system::mount("none", proc_path, "proc", 0, None)?;

    // Linux announces way too much information under /proc. Hide everything possibly dangerous.
    for path in [
        // ACPI
        "acpi",
        // ALSA
        "asound",
        // A neighbour to zoneinfo
        "buddyinfo",
        // Contains PCI stuff
        "bus",
        // Potential monotonic counters
        "cgroups",
        // init(1) arguments
        "cmdline",
        // ttys
        "consoles",
        // May contain info about disks
        "devices",
        // Disk statistics, includes monotonic counters as well as private information
        "diskstats",
        // Contains info on DMA channels
        "dma",
        // Usually only contains information about RTC, which is fine, but nvram and NVIDIA data is
        // common too
        "driver",
        // Contains information about framebuffers and related kernel modules
        "fb",
        // Contains statistics and configuration of physical filesystems, journals, etc.
        "fs",
        // Interrupts info, including references to PCI and modules
        "interrupts",
        // Contains kernel memory map. Only reveals absolute addresses to root, but just in case.
        "iomem",
        // Contains kernel memory map. Only reveals absolute addresses to root, but just in case.
        "ioports",
        // Interrupts stuff
        "irq",
        // Kernel symbols, including those of modules. Only reveals absolute addresses to root.
        "kallsyms",
        // Kernel memory
        "kcore",
        // Keyrings
        "key-users",
        // Keyring
        "keys",
        // Exactly what it says on the tin. Should be mode 400 anyway, but just in case.
        "kmsg",
        // May be used to differentiate between testing scenarios
        "loadavg",
        // RAID
        "mdstat",
        // /proc/meminfo is not namespaced, which means nothing inside it can really be trusted
        "meminfo",
        // Modules. May be useful for vulnerability enumeration.
        "misc",
        // Currently loaded modules
        "modules",
        // Flash memory information
        "mtd",
        // Contains information on block devices
        "partitions",
        // Load average and alike
        "pressure",
        // Contains way too much information about the scheduler
        "sched_debug",
        // Scheduler statistics, incldues monotonic counters
        "schedstat",
        // SCSI
        "scsi",
        // Monotonic counters
        "softirqs",
        // This one is complicated. It contains some information tools like time(1) may find useful,
        // but it also reveals the count of processes started since uptime, the uptime itself, and
        // other counters which may theoretically be used to learn information about the state of
        // the judge.
        "stat",
        // May reveal paths outside sandbox
        "swaps",
        // Reveals hardware
        "sys/dev",
        // A monotonic counter
        "uptime",
        // Memory statistics, contains various monotonic counters
        "vmstat",
        // CPU and memory info, includes monotonic counters
        "zoneinfo",
    ] {
        let target = PathBuf::from(proc_path).join(path);

        let metadata = std::fs::metadata(&target);

        if let Err(ref e) = metadata {
            if let std::io::ErrorKind::NotFound = e.kind() {
                // If a file does not exist, there's nothing to hide
                continue;
            }
        }

        let metadata = metadata.with_context(|| format!("Failed to stat {target:?}"))?;

        let source = if metadata.is_dir() {
            "/emptydir"
        } else {
            "/emptyfile" // /dev/null cannot be bound read-only
        };

        system::bind_mount(source, &target)
            .with_context(|| format!("Failed to hide .../proc/{path}"))?;
        system::bind_mount_opt("none", target, system::MS_REMOUNT | system::MS_RDONLY)
            .with_context(|| format!("Failed to remount .../proc/{path} read-only"))?;
    }

    Ok(())
}

pub fn reset_pidns() -> Result<()> {
    std::fs::write("/proc/sys/kernel/ns_last_pid", "1\n")
        .context("Failed to sysctl kernel.ns_last_pid=1")?;
    Ok(())
}
