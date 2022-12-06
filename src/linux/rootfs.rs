use crate::linux::{ids, mountns, procs, system};
use anyhow::{anyhow, Context, Result};
use std::ffi::{OsStr, OsString};
use std::io::{BufRead, ErrorKind};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Component, Path, PathBuf};

pub struct DiskQuotas {
    pub space: u64,
    pub max_inodes: u64,
}

pub fn create_rootfs(root: &std::path::Path) -> Result<()> {
    // We need to mount an image, and also add some directories to the hierarchy.
    //
    // We can't use overlayfs: it doesn't work as expected when a lowerdir contains child mounts
    // (namely, it doesn't duplicate them), and that's rather common. In fact, mount(2) even fails
    // with EINVAL in this case if you're not being careful enough.
    //
    // Therefore we create a root in tmpfs from scratch, and bind-mount all top-level directories
    // from the image, and then simply add the required directories.

    // Create the new root directory
    std::fs::create_dir("/root").context("Failed to mkdir /root")?;

    // Mount directories from image
    for entry in std::fs::read_dir(root).context("Failed to read root directory")? {
        let entry = entry.context("Failed to read root directory")?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|name| anyhow!("File name {name:?} is not UTF-8"))?;
        // Don't clone directories we're going to mount over anyway, and also /sys, because it's too
        // dangerous
        if name != "space" && name != "dev" && name != "proc" && name != "tmp" && name != "sys" {
            let source_path = entry
                .path()
                .into_os_string()
                .into_string()
                .map_err(|path| anyhow!("Path {path:?} is not UTF-8"))?;

            let target_path = format!("/root/{name}");

            let file_type = entry.file_type().context("Failed to acquire file type")?;

            if file_type.is_symlink() {
                // Bind-mounting a symlink might be a bad idea
                let link_target =
                    std::fs::read_link(entry.path()).context("Failed to read link")?;
                std::os::unix::fs::symlink(&link_target, &target_path).with_context(|| {
                    format!("Failed to symlink {link_target:?} to {target_path}")
                })?;
                continue;
            } else if file_type.is_dir() {
                std::fs::create_dir(&target_path)
                    .with_context(|| format!("Failed to mkdir {target_path}"))?;
            } else {
                std::fs::File::create(&target_path)
                    .with_context(|| format!("Failed to touch {target_path}"))?;
            }

            system::bind_mount(&source_path, &target_path)
                .with_context(|| format!("Failed to bind-mount {source_path} to {target_path}"))?;
            system::bind_mount_opt("none", &target_path, system::MS_REMOUNT | system::MS_RDONLY)
                .with_context(|| format!("Failed to remount {target_path} read-only"))?;
        }
    }

    // Mount ephemeral directories
    for name in ["space", "dev", "proc", "tmp"] {
        let path = format!("/root/{name}");
        std::fs::create_dir(&path).with_context(|| format!("Failed to mkdir {path}"))?;
    }
    // Don't mount /space and /tmp immediately, we'll mount them later
    // Mount /dev
    system::bind_mount_opt("/dev", "/root/dev", system::MS_REC)
        .context("Failed to bind-mount /root/dev")?;
    system::bind_mount_opt("none", "/root/dev", system::MS_REMOUNT | system::MS_RDONLY)
        .context("Failed to remount /root/dev read-only")?;

    Ok(())
}

pub fn configure_rootfs() -> Result<()> {
    // Mount /proc. This has to happen inside the pidns.
    procs::mount_procfs("/root/proc").context("Failed to mount /root/proc")?;

    // We want to unmount /oldroot and others, so we need to switch to a new mount namespace. But we
    // don't want mounts to get locked, so the user namespace has to stay the same.
    mountns::unshare_mountns().context("Failed to unshare mount namespace")?;
    system::change_propagation("/oldroot", system::MS_PRIVATE)
        .context("Failed to change propagation of /oldroot")?;
    system::umount_opt("/oldroot", system::MNT_DETACH).context("Failed to unmount /oldroot")?;

    Ok(())
}

pub fn enter_rootfs() -> Result<()> {
    // This function used to pivot_root. Unfortunately, this proved difficult to get right.
    //
    // The major benefit of pivot_root is that it allows us to unmount the old root, which lets us
    // not worry that much about accidentally revealing the host's filesystem -- it's simply
    // inaccessible from inside the sandbox, assuming that the pid namespace is correctly isolated.
    //
    // There were two caveats here.
    //
    // Firstly, instead of pivot_root'ing directly into .../isolated/root, we pivot_root'ed into
    // .../isolated, first and chroot into /root second. This is because the resulting environment
    // must be chrooted, because that prevents unshare(CLONE_NEWUSER) from succeeding inside the
    // namespace. This is, in fact, the only way to do this without spooky action at a distance,
    // that I am aware of. This used to be an implementation detail of the Linux kernel, but should
    // perhaps be considered more stable now. The necessity to disable user namespaces comes not
    // from their intrinsic goal but from the fact that they enable all other namespaces to work
    // without root, and while most of them are harmless (e.g. network and PID namespaces), others
    // may be used to bypass quotas (not other security measures, though). One prominent example is
    // mount namespace, which enables the user to mount a read-write tmpfs without disk limits and
    // use it as unlimited temporary storage to exceed the memory limit.
    //
    // However, the more problematic part was that pivot_root does not interact well with user and
    // mount namespaces. We want mounts from the main process to propagate into the sandbox, but, as
    // far as I know, pivot_root does not support non-private mounts. This means that we must use
    // chroot, and if we want to obtain the level of security pivot_root might otherwise grant, we
    // have to call pivot_root earlier, in the main process.

    mountns::unshare_mountns().context("Failed to unshare mount namespace")?;

    // Chroot into /root
    std::env::set_current_dir("/root").context("Failed to chdir to /root")?;
    nix::unistd::chroot(".").context("Failed to chroot into /root")?;

    Ok(())
}

pub fn reset(quotas: &DiskQuotas) -> Result<()> {
    // Unmount /space and everything beneath
    unmount_recursively("/root/space", true)?;

    // (Re)mount /space
    system::mount(
        "none",
        "/root/space",
        "tmpfs",
        system::MS_NOSUID,
        Some(format!("size={},nr_inodes={}", quotas.space, quotas.max_inodes).as_ref()),
    )
    .context("Failed to mount tmpfs on /root/space")?;
    std::os::unix::fs::chown(
        "/root/space",
        Some(ids::INTERNAL_USER_UID),
        Some(ids::INTERNAL_USER_GID),
    )
    .context("Failed to chown /root/space")?;

    // (Re)mount /dev/shm
    std::fs::create_dir("/root/space/.shm").context("Failed to mkdir /root/space/.shm")?;
    if let Err(e) = system::umount("/root/dev/shm") {
        if e.kind() == ErrorKind::InvalidInput {
            // This means /dev/shm is not a mountpoint, which is fine the first time we reset the fs
        } else {
            return Err(e).context("Failed to unmount /root/dev/shm");
        }
    }
    system::bind_mount("/root/space/.shm", "/root/dev/shm")
        .context("Failed to bind-mount /root/space/.shm to /root/dev/shm")?;

    // (Re)mount /tmp
    std::fs::create_dir("/root/space/.tmp").context("Failed to mkdir /root/space/.tmp")?;
    std::os::unix::fs::chown(
        "/root/space/.tmp",
        Some(ids::INTERNAL_ROOT_UID),
        Some(ids::INTERNAL_ROOT_GID),
    )
    .context("Failed to chown /root/space/.tmp")?;
    std::fs::set_permissions(
        "/root/space/.tmp",
        std::os::unix::fs::PermissionsExt::from_mode(0o1777),
    )
    .context("Failed to chmod /root/space/.tmp")?;
    if let Err(e) = system::umount("/root/tmp") {
        if e.kind() == ErrorKind::InvalidInput {
            // This means /tmp is not a mountpoint, which is fine the first time we reset the fs
        } else {
            return Err(e).context("Failed to unmount /root/tmp");
        }
    }
    system::bind_mount("/root/space/.tmp", "/root/tmp")
        .context("Failed to bind-mount /root/space/.tmp to /root/tmp")?;

    // Reset pseudoterminals. On linux, devptsfs uses IDA[1], which allocates IDs sequentially,
    // returning the first unused ID each time, so simply deleting everything from /dev/pts works.
    // [1]: https://www.kernel.org/doc/htmldocs/kernel-api/idr.html
    for entry in std::fs::read_dir("/root/dev/pts").context("Failed to readdir /root/dev/pts")? {
        let entry = entry.context("Failed to readdir /root/dev/pts")?;
        if let Ok(file_name) = entry.file_name().into_string() {
            if file_name.parse::<u64>().is_ok() {
                std::fs::remove_file(entry.path())
                    .with_context(|| format!("Failed to rm {:?}", entry.path()))?;
            }
        }
    }

    Ok(())
}

// Unmount everything beneath prefix recursively. Does not unmount prefix itself.
fn unmount_recursively(prefix: &str, inclusive: bool) -> Result<()> {
    let prefix_slash = format!("{prefix}/");

    let file = std::fs::File::open("/proc/self/mounts")
        .context("Failed to open /proc/self/mounts for reading")?;

    let mut vec = Vec::new();
    for line in std::io::BufReader::new(file).lines() {
        let line = line.context("Failed to read /proc/self/mounts")?;
        let mut it = line.split(' ');
        it.next().context("Invalid format of /proc/self/mounts")?;
        let target_path = it.next().context("Invalid format of /proc/self/mounts")?;
        if target_path.starts_with(&prefix_slash) || (inclusive && target_path == prefix) {
            vec.push(target_path.to_string());
        }
    }

    for path in vec.into_iter().rev() {
        system::umount(&path).with_context(|| format!("Failed to unmount {path}"))?;
    }

    Ok(())
}

fn resolve_abs(
    path: &Path,
    root: &[u8],
    mut acc: Vec<u8>,
    link_level: usize,
) -> std::io::Result<PathBuf> {
    if link_level > 255 {
        return Err(std::io::Error::from(ErrorKind::FilesystemLoop));
    }
    for component in path.components() {
        match component {
            Component::Prefix(_) => {
                // Impossible on *nix
                unreachable!()
            }
            Component::RootDir => {
                acc.truncate(root.len());
            }
            Component::CurDir => {}
            Component::ParentDir => {
                if acc.len() > root.len() {
                    acc.truncate(acc.iter().rposition(|&r| r == b'/').unwrap());
                }
            }
            Component::Normal(part) => {
                let cwd_acc_len = acc.len();
                acc.push(b'/');
                acc.extend_from_slice(part.as_bytes());

                // If readlink fails, it's either because we get EINVAL, which means it's not a
                // symlink and the error is safe to ignore, or something worse, e.g. ENOENT, but if
                // it's critical, it's going to be handled later anyway, when the path is used
                if let Ok(link_target) = std::fs::read_link(OsStr::from_bytes(&acc)) {
                    acc.truncate(cwd_acc_len);
                    acc = resolve_abs(&link_target, root, acc, link_level + 1)?
                        .into_os_string()
                        .into_vec();
                }
            }
        }
    }
    Ok(PathBuf::from(OsString::from_vec(acc)))
}

pub fn resolve_abs_box_root<P: AsRef<Path>>(path: P) -> std::io::Result<PathBuf> {
    resolve_abs(path.as_ref(), b"/root", b"/root/space".to_vec(), 0)
}

pub fn resolve_abs_old_root<P: AsRef<Path>>(path: P) -> std::io::Result<PathBuf> {
    resolve_abs(path.as_ref(), b"/oldroot", b"/oldroot".to_vec(), 0)
}
