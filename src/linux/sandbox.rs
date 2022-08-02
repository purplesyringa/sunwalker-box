use crate::linux::system;
use anyhow::{bail, Context, Result};
use nix::{
    libc,
    libc::{c_char, c_int, CLONE_NEWIPC, CLONE_NEWNET, CLONE_NEWUTS, CLONE_SYSVSEM},
};
use std::io::BufRead;
use std::os::unix::fs::PermissionsExt;

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
    if unsafe { libc::unshare(CLONE_NEWIPC | CLONE_NEWUTS | CLONE_SYSVSEM | CLONE_NEWNET) } != 0 {
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
    // IPC namespace. This is critical to clean up correctly, because creating an IPC namespace in
    // the kernel is terribly slow, and *deleting* it actually happens asynchronously. This
    // basically means that if we create and drop IPC namespaces quickly enough, the deleting queue
    // will overflow and we won't be able to do any IPC operation (including creation of an IPC
    // namespace) for a while--something to avoid at all costs.

    // Clean up System V message queues
    {
        let file =
            std::fs::File::open("/proc/sysvipc/msg").context("Failed to open /proc/sysvipc/msg")?;

        let mut msqids: Vec<c_int> = Vec::new();

        // Skip header
        for line in std::io::BufReader::new(file).lines().skip(1) {
            let line = line.context("Failed to read /proc/sysvipc/msg")?;
            let mut it = line.trim().split_ascii_whitespace();

            it.next().context("Invalid format of /proc/sysvipc/msg")?;

            let msqid = it
                .next()
                .context("Invalid format of /proc/sysvipc/msg")?
                .parse()
                .context("Invalid format of msqid in /proc/sysvipc/msg")?;

            msqids.push(msqid);
        }

        for msqid in msqids {
            if unsafe { libc::msgctl(msqid, libc::IPC_RMID, std::ptr::null_mut()) } == -1 {
                return Err(std::io::Error::last_os_error())
                    .with_context(|| format!("Failed to delete System V message queue #{msqid}"));
            }
        }
    }

    // Clean up System V semaphores sets
    {
        let file =
            std::fs::File::open("/proc/sysvipc/sem").context("Failed to open /proc/sysvipc/sem")?;

        let mut semids: Vec<c_int> = Vec::new();

        // Skip header
        for line in std::io::BufReader::new(file).lines().skip(1) {
            let line = line.context("Failed to read /proc/sysvipc/sem")?;
            let mut it = line.trim().split_ascii_whitespace();

            it.next().context("Invalid format of /proc/sysvipc/sem")?;

            let semid = it
                .next()
                .context("Invalid format of /proc/sysvipc/sem")?
                .parse()
                .context("Invalid format of semid in /proc/sysvipc/sem")?;

            semids.push(semid);
        }

        for semid in semids {
            if unsafe { libc::semctl(semid, 0, libc::IPC_RMID) } == -1 {
                return Err(std::io::Error::last_os_error())
                    .with_context(|| format!("Failed to delete System V semaphore #{semid}"));
            }
        }
    }

    // Clean up System V shared memory segments
    {
        let file =
            std::fs::File::open("/proc/sysvipc/shm").context("Failed to open /proc/sysvipc/shm")?;

        let mut shmids: Vec<c_int> = Vec::new();

        // Skip header
        for line in std::io::BufReader::new(file).lines().skip(1) {
            let line = line.context("Failed to read /proc/sysvipc/shm")?;
            let mut it = line.trim().split_ascii_whitespace();

            it.next().context("Invalid format of /proc/sysvipc/shm")?;

            let shmid = it
                .next()
                .context("Invalid format of /proc/sysvipc/shm")?
                .parse()
                .context("Invalid format of shmid in /proc/sysvipc/shm")?;

            shmids.push(shmid);
        }

        for shmid in shmids {
            if unsafe { libc::shmctl(shmid, libc::IPC_RMID, std::ptr::null_mut()) } == -1 {
                return Err(std::io::Error::last_os_error())
                    .with_context(|| format!("Failed to delete System V shared memory #{shmid}"));
            }
        }
    }

    // POSIX message queues are stored in /dev/mqueue as files, which we can simply unlink.
    for entry in std::fs::read_dir("/dev/mqueue").context("Failed to readdir /dev/mqueue")? {
        let entry = entry.context("Failed to readdir /dev/mqueue")?;
        std::fs::remove_file(entry.path())
            .with_context(|| format!("Failed to rm {:?}", entry.path()))?;
    }

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

    // Make various temporary directories
    std::fs::create_dir("/tmp/sunwalker_box/rootfs")
        .context("Failed to mkdir /tmp/sunwalker_box/rootfs")?;
    std::fs::create_dir("/tmp/sunwalker_box/ns")
        .context("Failed to mkdir /tmp/sunwalker_box/ns")?;
    std::fs::create_dir("/tmp/sunwalker_box/emptydir")
        .context("Failed to mkdir /tmp/sunwalker_box/emptydir")?;

    Ok(())
}

pub fn create_dev_copy() -> Result<()> {
    std::fs::create_dir("/tmp/sunwalker_box/dev")
        .context("Failed to mkdir /tmp/sunwalker_box/dev")?;

    for name in [
        "null", "full", "zero", "urandom", "random", "stdin", "stdout", "stderr", "fd",
    ] {
        let source = format!("/dev/{name}");
        let target = format!("/tmp/sunwalker_box/dev/{name}");
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

    // Mount /dev/mqueue. This has to happen inside the IPC namespace, because mqueuefs is attached
    // to the namespace of the process that mounted it, and this has to happen before unsharing
    // userns because mqueuefs can only be mounted by real root.
    std::fs::create_dir("/tmp/sunwalker_box/dev/mqueue")
        .context("Failed to mkdir /tmp/sunwalker_box/dev/mqueue")?;
    system::mount("mqueue", "/tmp/sunwalker_box/dev/mqueue", "mqueue", 0, None)
        .context("Failed to mount mqueue on /tmp/sunwalker_box/dev/mqueue")?;
    // rwxrwxrwt
    std::fs::set_permissions(
        "/tmp/sunwalker_box/dev/mqueue",
        std::fs::Permissions::from_mode(0o1777),
    )
    .context("Failed to make /tmp/sunwalker_box/mqueue dev/world-writable")?;

    // Mount /dev/{pts,ptmx}
    std::fs::create_dir("/tmp/sunwalker_box/dev/pts")
        .context("Failed to mkdir /tmp/sunwalker_box/dev/pts")?;
    system::mount(
        "devpts",
        "/tmp/sunwalker_box/dev/pts",
        "devpts",
        system::MS_NOSUID | system::MS_NOEXEC,
        Some("mode=666,ptmxmode=666"),
    )
    .context("Failed to mount devpts at /tmp/sunwalker_box/dev/pts")?;

    std::fs::write("/tmp/sunwalker_box/dev/ptmx", "")
        .context("Failed to touch /tmp/sunwalker_box/dev/ptmx")?;
    system::bind_mount(
        "/tmp/sunwalker_box/dev/pts/ptmx",
        "/tmp/sunwalker_box/dev/ptmx",
    )
    .context(
        "Failed to bind-mount /tmp/sunwalker_box/dev/pts/ptmx to /tmp/sunwalker_box/dev/ptmx",
    )?;

    // This directory will be mounted onto later
    std::fs::create_dir("/tmp/sunwalker_box/dev/shm")
        .context("Failed to mkdir /tmp/sunwalker_box/dev/shm")?;

    Ok(())
}
