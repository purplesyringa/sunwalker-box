use crate::linux::system;
use anyhow::{bail, Context, Result};
use nix::{
    libc,
    libc::{c_char, CLONE_NEWNET, CLONE_NEWUTS, CLONE_SYSVSEM},
};

pub fn sanity_checks() -> Result<()> {
    // suid_dumpable = 1 means PR_SET_DUMPABLE does not trigger automatically on setuid, which is
    // an escape vector. suid_dumpable = 2 is somewhat vulnerable (though only with particular
    // userland) on some old kernel versions, but no one uses them anymore.
    let suid_dumpable = std::fs::read_to_string("/proc/sys/fs/suid_dumpable")?;
    if suid_dumpable == "1\n" {
        bail!("suid_dumpable is set to 1, unable to continue safely");
    }

    // Only cgroup v2 is supported. It's used by default on new distributions, so it shouldn't be a
    // problem. Cgroup v1 running in v2-compatibility mode could theoretically work, but we use
    // common controllers so it's unlikely that they're all wired to v2 mode instead of v1 but
    // somehow switching to complete v2 is impossible.
    let fstype = nix::sys::statfs::statfs("/sys/fs/cgroup")
        .context("cgroups are not available at /sys/fs/cgroup")?
        .filesystem_type();
    match fstype.0 as i64 {
        libc::CGROUP2_SUPER_MAGIC => {}
        libc::TMPFS_MAGIC => {
            bail!(
                "cgroups v1 seems to be mounted at /sys/fs/cgroup. sunwalker requires cgroups v2. \
                 Please configure your kernel and/or distribution to use cgroups v2"
            );
        }
        _ => {
            bail!(
                "Unknown filesystem type at /sys/fs/cgroup. sunwalker requires cgroups v2. Please \
                 configure your kernel and/or distribution to use cgroups v2"
            );
        }
    }

    Ok(())
}

pub fn unshare_persistent_namespaces() -> Result<()> {
    if unsafe { libc::unshare(CLONE_NEWUTS | CLONE_SYSVSEM | CLONE_NEWNET) } != 0 {
        return Err(std::io::Error::last_os_error()).context("Failed to unshare namespaces");
    }

    // Configure UTS namespace
    let domain_name = "sunwalker";
    let host_name = "box";
    if unsafe { libc::setdomainname(domain_name.as_ptr() as *const c_char, domain_name.len()) }
        == -1
    {
        return Err(std::io::Error::last_os_error()).context("Failed to set domain name");
    }
    if unsafe { libc::sethostname(host_name.as_ptr() as *const c_char, host_name.len()) } == -1 {
        return Err(std::io::Error::last_os_error()).context("Failed to set host name");
    }

    // Will a reasonable program ever use a local network interface? Theoretically, I can see a
    // runtime with built-in multiprocessing support use a TCP socket on localhost for IPC, but
    // practically, the chances are pretty low and getting the network up takes time, so I'm leaving
    // it disabled for now.
    //
    // The second reason is that enabling it not as easy as flicking a switch. Linux collects
    // statistics on network interfaces, so the the network interfaces have to be re-created every
    // time to prevent data leaks. The lo interface is unique in the way that it always exists in
    // the netns and can't be deleted or recreated, according to a comment in Linux kernel:
    //     The loopback device is special if any other network devices
    //     is present in a network namespace the loopback device must
    //     be present. Since we now dynamically allocate and free the
    //     loopback device ensure this invariant is maintained by
    //     keeping the loopback device as the first device on the
    //     list of network devices.  Ensuring the loopback devices
    //     is the first device that appears and the last network device
    //     that disappears.
    //
    // However, we can create a dummy interface and assign the local addresses to it rather than lo.
    // It would still have to be re-created, though, and that takes precious time, 50 ms for me. And
    // then there is a problem with IPv6--::1 cannot be assigned to anything but lo due to a quirk
    // in the interpretation of the IPv6 RFC by the Linux kernel.

    // Bring lo down
    interfaces::Interface::get_by_name("lo")
        .context("Failed to get lo interface")?
        .context("lo interface is missing")?
        .set_up(false)
        .context("Failed to bring lo down")?;

    Ok(())
}

pub fn reset_persistent_namespaces() -> Result<()> {
    // Network namespaces are devised to isolate every network device the server has access to from
    // the programs, so we only really need to care about information stored by the kernel
    // internally. This includes statistics, which we nullify by bringing lo down, port occupation
    // statuses, and perhaps something else. Luckily, it seems like we don't have to do anything at
    // all.
    //
    // Many address families can only be used if a capable interface is available, and the only
    // interface we provide, lo, is down. Management protocols, such as AF_KEY, AF_NETLINK,
    // AF_PACKET, and AF_VSOCK, demand capabilities. Other protocols, such as DECnet and Bluetooth,
    // only work in the root network namespace.
    //
    // UNIX domain sockets are either pathname-based and therefore subject to automatic cleanup due
    // to filesystem reset, or unnamed, which means they don't have to be cleaned up, or abstract,
    // which are closed automatically when the last reference dies (and it does die because we kill
    // processes).

    Ok(())
}

pub fn enter_working_area() -> Result<()> {
    // Create per-box working area
    std::fs::create_dir_all("/tmp/sunwalker_box")
        .context("Failed to create /tmp/sunwalker_box directory")?;

    // Mount tmpfs on the working area
    system::mount("none", "/tmp/sunwalker_box", "tmpfs", 0, None)
        .context("Failed to mount tmpfs on /tmp/sunwalker_box")?;

    // Make various temporary directories and files
    std::fs::create_dir("/tmp/sunwalker_box/emptydir")
        .context("Failed to mkdir /tmp/sunwalker_box/emptydir")?;
    std::fs::write("/tmp/sunwalker_box/emptyfile", [])
        .context("Failed to touch /tmp/sunwalker_box/emptyfile")?;

    // Move old root and pivot_root
    std::fs::create_dir("/tmp/sunwalker_box/oldroot")
        .context("Failed to mkdir /tmp/sunwalker_box/oldroot")?;
    std::env::set_current_dir("/tmp/sunwalker_box")
        .context("Failed to chdir to /tmp/sunwalker_box")?;
    nix::unistd::pivot_root(".", "oldroot").context("Failed to pivot_root")?;
    std::env::set_current_dir("/").context("Failed to chdir to /")?;

    // Get /proc working
    std::fs::create_dir("/proc").context("Failed to mkdir /proc")?;
    system::bind_mount("/oldroot/proc", "/proc")
        .context("Failed to bind-mount /oldroot/proc to /proc")?;

    system::change_propagation("/", system::MS_SHARED | system::MS_REC)
        .expect("Failed to change propagation to shared");

    Ok(())
}

pub fn create_dev_copy() -> Result<()> {
    std::fs::create_dir("/dev").context("Failed to mkdir /dev")?;

    for name in [
        "null", "full", "zero", "urandom", "random", "stdin", "stdout", "stderr", "tty", "fd",
    ] {
        let source = if name == "random" {
            "/oldroot/dev/urandom".to_string() // prevent entropy depletion
        } else {
            format!("/oldroot/dev/{name}")
        };
        let target = format!("/dev/{name}");
        let metadata = std::fs::symlink_metadata(&source)
            .with_context(|| format!("{source} does not exist (or oculd not be accessed)"))?;
        if metadata.is_symlink() {
            let symlink_target = std::fs::read_link(&source)
                .with_context(|| format!("Failed to readlink {source:?}"))?;
            std::os::unix::fs::symlink(&symlink_target, &target)
                .with_context(|| format!("Failed to ln -s {symlink_target:?} {target:?}"))?;
            continue;
        } else if metadata.is_dir() {
            std::fs::create_dir(&target).with_context(|| format!("Failed to mkdir {target:?}"))?;
        } else {
            std::fs::File::create(&target)
                .with_context(|| format!("Failed to touch {target:?}"))?;
        }
        system::bind_mount(&source, &target)
            .with_context(|| format!("Bind-mounting {source} to {target} failed"))?;
    }

    // Mount /dev/{pts,ptmx}
    std::fs::create_dir("/dev/pts").context("Failed to mkdir /dev/pts")?;
    system::mount(
        "devpts",
        "/dev/pts",
        "devpts",
        system::MS_NOSUID | system::MS_NOEXEC,
        Some("mode=666,ptmxmode=666"),
    )
    .context("Failed to mount devpts at /dev/pts")?;

    std::fs::write("/dev/ptmx", "").context("Failed to touch /dev/ptmx")?;
    system::bind_mount("/dev/pts/ptmx", "/dev/ptmx")
        .context("Failed to bind-mount /dev/pts/ptmx to /dev/ptmx")?;

    // These directories will be mounted onto later
    std::fs::create_dir("/dev/shm").context("Failed to mkdir /dev/shm")?;
    std::fs::create_dir("/dev/mqueue").context("Failed to mkdir /dev/mqueue")?;

    Ok(())
}
