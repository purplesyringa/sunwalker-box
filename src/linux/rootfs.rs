use crate::{
    linux::{ids, mountns, procs, system},
    log,
};
use anyhow::{anyhow, ensure, Context, Result};
use std::collections::HashMap;
use std::ffi::{OsStr, OsString};
use std::io::{BufRead, ErrorKind};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Component, Path, PathBuf};

#[derive(Clone)]
pub struct DiskQuotas {
    pub space: u64,
    pub max_inodes: u64,
}

pub struct RootfsState {
    committed_mount_points: HashMap<String, usize>,
    space_mounts_restore_actions: Vec<(String, String)>,
    is_committed: bool,
    quotas: DiskQuotas,
}

pub fn create_rootfs(root: &std::path::Path, quotas: DiskQuotas) -> Result<RootfsState> {
    // We need to mount an image, and also add some directories to the hierarchy.
    //
    // We can't use overlayfs: it doesn't work as expected when a lowerdir contains child mounts
    // (namely, it doesn't duplicate them), and that's rather common. In fact, mount(2) even fails
    // with EINVAL in this case if you're not being careful enough.
    //
    // Therefore we create a root in tmpfs from scratch, and bind-mount all top-level directories
    // from the image, and then simply add the required directories.

    // Create the new root directory
    std::fs::create_dir("/newroot").context("Failed to mkdir /newroot")?;

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
            log!("Mirroring /{name}");

            let source_path = entry
                .path()
                .into_os_string()
                .into_string()
                .map_err(|path| anyhow!("Path {path:?} is not UTF-8"))?;

            let target_path = format!("/newroot/{name}");

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
                std::fs::File::create_new(&target_path)
                    .with_context(|| format!("Failed to touch {target_path}"))?;
            }

            system::bind_mount(&source_path, &target_path)
                .with_context(|| format!("Failed to bind-mount {source_path} to {target_path}"))?;
            system::bind_mount_opt("none", &target_path, system::MS_REMOUNT | system::MS_RDONLY)
                .with_context(|| format!("Failed to remount {target_path} read-only"))?;
        }
    }

    // Mount ephemeral directories
    for path in [
        "/newroot/space",
        "/newroot/dev",
        "/newroot/proc",
        "/newroot/tmp",
        "/staging",
    ] {
        std::fs::create_dir(path).with_context(|| format!("Failed to mkdir {path}"))?;
    }
    // Mount /dev
    system::bind_mount_opt("/dev", "/newroot/dev", system::MS_REC)
        .context("Failed to bind-mount /newroot/dev")?;
    system::bind_mount_opt(
        "none",
        "/newroot/dev",
        system::MS_REMOUNT | system::MS_RDONLY,
    )
    .context("Failed to remount /newroot/dev read-only")?;

    // Remember current mounts so that we can restore the state on reset
    let mut state = RootfsState {
        committed_mount_points: HashMap::new(),
        space_mounts_restore_actions: Vec::new(),
        is_committed: false,
        quotas,
    };
    update_committed_mount_points(&mut state, &list_mounts()?);
    Ok(state)
}

pub fn configure_rootfs() -> Result<()> {
    // Mount /proc. This has to happen inside the pidns.
    procs::mount_procfs("/newroot/proc").context("Failed to mount /newroot/proc")?;

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
    // Firstly, instead of pivot_root'ing directly into .../isolated/newroot, we pivot_root'ed into
    // .../isolated, first and chroot into /newroot second. This is because the resulting
    // environment must be chrooted, because that prevents unshare(CLONE_NEWUSER) from succeeding
    // inside the namespace. This is, in fact, the only way to do this without spooky action at a
    // distance, that I am aware of. This used to be an implementation detail of the Linux kernel,
    // but should perhaps be considered more stable now. The necessity to disable user namespaces
    // comes not from their intrinsic goal but from the fact that they enable all other namespaces
    // to work without root, and while most of them are harmless (e.g. network and PID namespaces),
    // others may be used to bypass quotas (not other security measures, though). One prominent
    // example is mount namespace, which enables the user to mount a read-write tmpfs without disk
    // limits and use it as unlimited temporary storage to exceed the memory limit.
    //
    // However, the more problematic part was that pivot_root does not interact well with user and
    // mount namespaces. We want mounts from the main process to propagate into the sandbox, but, as
    // far as I know, pivot_root does not support non-private mounts. This means that we must use
    // chroot, and if we want to obtain the level of security pivot_root might otherwise grant, we
    // have to call pivot_root earlier, in the main process.

    mountns::unshare_mountns().context("Failed to unshare mount namespace")?;

    // Chroot into /newroot
    std::env::set_current_dir("/newroot").context("Failed to chdir to /newroot")?;
    nix::unistd::chroot(".").context("Failed to chroot into /newroot")?;

    Ok(())
}

fn update_committed_mount_points(state: &mut RootfsState, mounts: &[String]) {
    state.committed_mount_points.clear();
    for path in mounts {
        if path.starts_with("/newroot/") {
            if let Some(count) = state.committed_mount_points.get_mut(path) {
                *count += 1;
            } else {
                state.committed_mount_points.insert(path.to_string(), 1);
            }
        }
    }
}

pub fn commit(state: &mut RootfsState) -> Result<()> {
    ensure!(!state.is_committed, "Cannot commit rootfs twice");

    log!("Committing changes");

    let mounts = list_mounts()?;
    update_committed_mount_points(state, &mounts);
    state.is_committed = true;

    save_space_mounts(state, mounts)?;

    // Make a new read-only base
    system::mount(
        "none",
        "/newroot/space",
        "tmpfs",
        system::MS_REMOUNT | system::MS_RDONLY | system::MS_NOSUID,
        Some(
            format!(
                "size={},nr_inodes={}",
                state.quotas.space, state.quotas.max_inodes
            )
            .as_ref(),
        ),
    )
    .context("Failed to remount /newroot/space read-only")?;
    std::fs::create_dir("/base").context("Failed to mkdir /base")?;
    system::bind_mount("/newroot/space", "/base")
        .context("Failed to bind-mount /newroot/space to /base")?;
    system::umount("/newroot/space").context("Failed to unmount /newroot/space")?;

    // Mount overlayfs on /newroot/space
    std::fs::create_dir("/staging/upper").context("Failed to mkdir /staging/upper")?;
    std::fs::create_dir("/staging/work").context("Failed to mkdir /staging/work")?;
    system::mount(
        "none",
        "/newroot/space",
        "overlay",
        0,
        Some("lowerdir=/base,upperdir=/staging/upper,workdir=/staging/work"),
    )
    .context("Failed to mount overlayfs on /newroot/space")?;
    std::os::unix::fs::chown(
        "/newroot/space",
        Some(ids::EXTERNAL_USER_UID),
        Some(ids::EXTERNAL_USER_GID),
    )
    .context("Failed to chown /newroot/space")?;

    restore_space_mounts(state)?;

    Ok(())
}

fn save_space_mounts(state: &mut RootfsState, mounts: Vec<String>) -> Result<()> {
    std::fs::create_dir("/saved").context("Failed to mkdir /saved")?;

    for (i, path) in mounts.into_iter().enumerate() {
        if !path.starts_with("/newroot/space/") {
            continue;
        }

        let saved_path = format!("/saved/saved{i}");
        log!("Saving mount {path} -> {saved_path}");

        let metadata = std::fs::metadata(&path)
            .with_context(|| format!("Failed to get metadata of {path}"))?;
        if metadata.is_dir() {
            std::fs::create_dir(&saved_path)
                .with_context(|| format!("Failed to mkdir {saved_path}"))?;
        } else {
            std::fs::File::create_new(&saved_path)
                .with_context(|| format!("Failed to touch {saved_path}"))?;
        }

        system::bind_mount(&path, &saved_path)
            .with_context(|| format!("Failed to move mount {path} to {saved_path}"))?;
        state.space_mounts_restore_actions.push((saved_path, path));
    }

    for (_, path) in state.space_mounts_restore_actions.iter().rev() {
        system::umount(path).with_context(|| format!("Failed to unmount {path}"))?;
    }

    Ok(())
}

fn restore_space_mounts(state: &RootfsState) -> Result<()> {
    for (saved_path, path) in &state.space_mounts_restore_actions {
        log!("Restoring mount {saved_path} -> {path}");
        system::bind_mount(saved_path, path)
            .with_context(|| format!("Failed to bind-mount {saved_path} to {path}"))?;
    }
    Ok(())
}

fn mount_user_dir(state: &RootfsState, path: &str) -> Result<()> {
    system::mount(
        "none",
        path,
        "tmpfs",
        system::MS_NOSUID,
        Some(
            format!(
                "size={},nr_inodes={}",
                state.quotas.space, state.quotas.max_inodes
            )
            .as_ref(),
        ),
    )
    .with_context(|| format!("Failed to mount tmpfs on {path}"))?;

    std::os::unix::fs::chown(
        path,
        Some(ids::EXTERNAL_USER_UID),
        Some(ids::EXTERNAL_USER_GID),
    )
    .with_context(|| format!("Failed to chown {path}"))?;

    std::fs::set_permissions(path, std::os::unix::fs::PermissionsExt::from_mode(0o755))
        .with_context(|| format!("Failed to chmod {path}"))?;

    Ok(())
}

pub fn reset(state: &RootfsState) -> Result<()> {
    // Unmount all non-whitelisted mounts. Except for /proc/*, which is a nightmare, and
    // /dev/mqueue.
    let mut mount_points: HashMap<&str, usize> = HashMap::new();
    for (path, count) in &state.committed_mount_points {
        mount_points.insert(path, *count);
    }
    let mut paths_to_umount: Vec<String> = Vec::new();
    let mut current_mounts = Vec::new();
    for path in list_mounts()? {
        if (path.starts_with("/newroot/")
            && path != "/newroot/proc"
            && !path.starts_with("/newroot/proc/")
            && path != "/newroot/dev/mqueue")
            || path == "/staging"
        {
            match mount_points.get_mut(&path[..]) {
                Some(n) if *n > 0 => *n -= 1,
                _ => {
                    paths_to_umount.push(path);
                    continue;
                }
            }
        }
        current_mounts.push(path);
    }
    for path in paths_to_umount.into_iter().rev() {
        log!("Unmounting {path}");
        system::umount(&path).with_context(|| format!("Failed to unmount {path}"))?;
    }

    // /staging and (if not committed) /newroot/space have just been unmounted
    system::mount(
        "none",
        "/staging",
        "tmpfs",
        system::MS_NOSUID,
        Some(
            format!(
                "size={},nr_inodes={}",
                state.quotas.space, state.quotas.max_inodes
            )
            .as_ref(),
        ),
    )
    .context("Failed to mount tmpfs on /staging")?;

    log!("Mounting /space");
    if state.is_committed {
        std::fs::create_dir("/staging/upper").context("Failed to mkdir /staging/upper")?;
        std::fs::create_dir("/staging/work").context("Failed to mkdir /staging/work")?;
        system::umount("/newroot/dev/shm").context("Failed to unmount /newroot/dev/shm")?;
        system::umount("/newroot/tmp").context("Failed to unmount /newroot/tmp")?;
        system::umount_opt("/newroot/space", system::MNT_DETACH)
            .context("Failed to unmount /newroot/space")?;
        system::mount(
            "none",
            "/newroot/space",
            "overlay",
            0,
            Some("lowerdir=/base,upperdir=/staging/upper,workdir=/staging/work"),
        )
        .context("Failed to mount overlayfs on /newroot/space")?;
        std::os::unix::fs::chown(
            "/newroot/space",
            Some(ids::EXTERNAL_USER_UID),
            Some(ids::EXTERNAL_USER_GID),
        )
        .context("Failed to chown /newroot/space")?;
        restore_space_mounts(state)?;
    } else {
        mount_user_dir(state, "/newroot/space")?;
    }

    // (Re)mount /dev/shm and /tmp
    for (path, orig_path) in [
        ("/newroot/dev/shm", "/staging/shm"),
        ("/newroot/tmp", "/staging/tmp"),
    ] {
        std::fs::create_dir(orig_path).with_context(|| format!("Failed to mkdir {orig_path}"))?;
        std::os::unix::fs::chown(
            orig_path,
            Some(ids::EXTERNAL_ROOT_UID),
            Some(ids::EXTERNAL_ROOT_GID),
        )
        .with_context(|| format!("Failed to chown {orig_path}"))?;
        std::fs::set_permissions(
            orig_path,
            std::os::unix::fs::PermissionsExt::from_mode(0o1777),
        )
        .with_context(|| format!("Failed to chmod {orig_path}"))?;
        system::bind_mount(orig_path, path)
            .with_context(|| format!("Failed to bind-mount {orig_path} to {path}"))?;
    }

    // Reset pseudoterminals. On linux, devptsfs uses non-cyclic ida_alloc*, which allocates IDs
    // sequentially, returning the first unused ID each time, so simply deleting everything from
    // /dev/pts works. See https://www.kernel.org/doc/htmldocs/kernel-api/idr.html for more info.
    for entry in
        std::fs::read_dir("/newroot/dev/pts").context("Failed to readdir /newroot/dev/pts")?
    {
        let entry = entry.context("Failed to readdir /newroot/dev/pts")?;
        if let Ok(file_name) = entry.file_name().into_string() {
            if file_name.parse::<u64>().is_ok() {
                log!("Removing pty #{file_name}");
                std::fs::remove_file(entry.path())
                    .with_context(|| format!("Failed to rm {:?}", entry.path()))?;
            }
        }
    }

    Ok(())
}

fn list_mounts() -> Result<Vec<String>> {
    let file = std::fs::File::open("/proc/self/mounts")
        .context("Failed to open /proc/self/mounts for reading")?;

    let mut vec = Vec::new();
    for line in std::io::BufReader::new(file).lines() {
        let line = line.context("Failed to read /proc/self/mounts")?;
        let mut it = line.split(' ');
        it.next().context("Invalid format of /proc/self/mounts")?;
        let target_path = it.next().context("Invalid format of /proc/self/mounts")?;
        if target_path != "/oldroot" && !target_path.starts_with("/oldroot/") {
            vec.push(target_path.to_string());
        }
    }

    Ok(vec)
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
    resolve_abs(path.as_ref(), b"/newroot", b"/newroot/space".to_vec(), 0)
}

pub fn resolve_abs_old_root<P: AsRef<Path>>(path: P) -> std::io::Result<PathBuf> {
    resolve_abs(path.as_ref(), b"/oldroot", b"/oldroot".to_vec(), 0)
}
