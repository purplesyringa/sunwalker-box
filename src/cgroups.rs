use crate::ids;
use anyhow::{Context, Result};
use libc::pid_t;
use multiprocessing::Object;
use rand::Rng;
use std::ffi::OsStr;
use std::io::{Read, Write};
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::time::Duration;

#[derive(Object)]
pub struct Cgroup {
    core_cgroup_fd: openat::Dir,
    id: String,
}

#[derive(Object)]
pub struct UserCgroup {
    proc_cgroup_fd: openat::Dir,
    box_id: String,
    dropped: bool,
}

impl Cgroup {
    pub fn new(core: u64) -> Result<Self> {
        // Create a cgroup for the core; it must be an immediate child of the root cgroup
        let dir = format!("/sys/fs/cgroup/sunwalker-box-core-{core}");
        std::fs::create_dir_all(&dir).with_context(|| format!("Failed to mkdir {dir}"))?;
        std::fs::write(
            format!("{dir}/cgroup.subtree_control"),
            "+cpu +memory +pids",
        )
        .context("Failed to enable cgroup controllers")?;

        // sysfs is unavailable inside the box, so we have to acquire a file descriptor
        let core_cgroup_fd = openat::Dir::open(&dir).context("Failed to open cgroup directory")?;

        chown_cgroup(
            &core_cgroup_fd,
            Some(ids::EXTERNAL_ROOT_UID),
            Some(ids::EXTERNAL_ROOT_GID),
        )
        .with_context(|| format!("Failed to chown {dir}"))?;

        // Set core
        std::fs::write(format!("{dir}/cpuset.cpus"), format!("{core}\n"))
            .with_context(|| format!("Failed to write to {dir}/cpuset.cpus"))?;
        std::fs::write(format!("{dir}/cpuset.cpus.partition"), "root\n")
            .context("Failed to switch partition type to 'root'")?;

        // Create a cgroup for the manager
        std::fs::create_dir_all(format!("{dir}/manager"))
            .with_context(|| format!("Failed to mkdir {dir}/manager"))?;
        chown_cgroup(
            &core_cgroup_fd
                .sub_dir("manager")
                .with_context(|| format!("Failed to open {dir}/manager"))?,
            Some(ids::EXTERNAL_ROOT_UID),
            Some(ids::EXTERNAL_ROOT_GID),
        )?;

        // Create a cgroup for this particular process
        let mut rng = rand::thread_rng();
        let id: String = (0..10)
            .map(|_| rng.sample(rand::distributions::Alphanumeric) as char)
            .collect();
        std::fs::create_dir_all(format!("{dir}/proc-{id}"))
            .with_context(|| format!("Failed to mkdir {dir}/proc-{id}"))?;
        std::fs::write(
            format!("{dir}/proc-{id}/cgroup.subtree_control"),
            "+cpu +memory +pids",
        )
        .context("Failed to enable cgroup controllers")?;
        chown_cgroup(
            &core_cgroup_fd
                .sub_dir(format!("proc-{id}"))
                .with_context(|| format!("Failed to open {dir}/proc-{id}"))?,
            Some(ids::EXTERNAL_ROOT_UID),
            Some(ids::EXTERNAL_ROOT_GID),
        )?;

        Ok(Cgroup { core_cgroup_fd, id })
    }

    pub fn add_self_as_manager(&self) -> Result<()> {
        self.core_cgroup_fd
            .write_file("manager/cgroup.procs", 0o700)
            .context("Failed to open cgroup.procs for writing")?
            .write(b"0\n")
            .context("Failed to move process")?;
        Ok(())
    }

    pub fn create_user_cgroup(&self) -> Result<UserCgroup> {
        // As several boxes may share a core, we can't use a fixed cgroup name
        let mut rng = rand::thread_rng();
        let box_id: String = (0..10)
            .map(|_| rng.sample(rand::distributions::Alphanumeric) as char)
            .collect();

        let box_dir = format!("proc-{}/box-{box_id}", self.id);
        self.core_cgroup_fd
            .create_dir(&box_dir, 0o700)
            .with_context(|| format!("Failed to mkdir {box_dir}"))?;
        chown_cgroup(
            &self
                .core_cgroup_fd
                .sub_dir(&box_dir)
                .with_context(|| format!("Failed to open {box_dir}"))?,
            Some(ids::INTERNAL_ROOT_UID),
            Some(ids::INTERNAL_ROOT_GID),
        )?;

        Ok(UserCgroup {
            proc_cgroup_fd: self
                .core_cgroup_fd
                .sub_dir(format!("proc-{}", self.id))
                .with_context(|| format!("Failed to open proc-{}", self.id))?,
            box_id,
            dropped: false,
        })
    }

    fn kill_user_processes(&self) -> Result<()> {
        self.core_cgroup_fd
            .write_file(format!("proc-{}/cgroup.kill", self.id), 0o700)
            .context("Failed to open cgroup.kill for writing")?
            .write(b"1\n")
            .context("Failed to kill cgroup")?;
        Ok(())
    }

    pub fn destroy(self) -> Result<()> {
        self.kill_user_processes()?;
        remove_cgroup(&self.core_cgroup_fd, format!("proc-{}", self.id).as_ref())?;
        Ok(())
    }

    pub fn try_clone(&self) -> Result<Self> {
        Ok(Cgroup {
            // Built-in try_clone erroneously does not set CLOEXEC
            core_cgroup_fd: unsafe {
                openat::Dir::from_raw_fd(
                    nix::fcntl::fcntl(
                        self.core_cgroup_fd.as_raw_fd(),
                        nix::fcntl::FcntlArg::F_DUPFD_CLOEXEC(0),
                    )
                    .context("Failed to clone file descriptor")?,
                )
            },
            id: self.id.clone(),
        })
    }
}

impl UserCgroup {
    pub fn add_process(&self, pid: pid_t) -> Result<()> {
        self.proc_cgroup_fd
            .write_file(format!("box-{}/cgroup.procs", self.box_id), 0o700)
            .context("Failed to open cgroup.procs for writing")?
            .write(format!("{pid}\n").as_ref())
            .context("Failed to move process")?;
        Ok(())
    }

    pub fn kill_processes(&self) -> Result<()> {
        self.proc_cgroup_fd
            .write_file(format!("box-{}/cgroup.kill", self.box_id), 0o700)
            .context("Failed to open cgroup.kill for writing")?
            .write(b"1\n")
            .context("Failed to kill cgroup")?;
        Ok(())
    }

    pub fn set_memory_limit(&self, limit: usize) -> Result<()> {
        self.proc_cgroup_fd
            .write_file(format!("box-{}/memory.max", self.box_id), 0o700)
            .context("Failed to open memory.max for writing")?
            .write(format!("{limit}\n").as_ref())
            .context("Failed to set memory limit")?;
        self.proc_cgroup_fd
            .write_file(format!("box-{}/memory.oom.group", self.box_id), 0o700)
            .context("Failed to open memory.oom.group for writing")?
            .write(b"1\n")
            .context("Failed to enable OOM grouping")?;
        Ok(())
    }

    pub fn get_cpu_stats(&self) -> Result<CpuStats> {
        let mut buf = String::new();
        self.proc_cgroup_fd
            .open_file(format!("box-{}/cpu.stat", self.box_id))
            .context("Failed to open cpu.stat for reading")?
            .read_to_string(&mut buf)
            .context("Failed to read cpu.stat")?;

        let mut stat = CpuStats {
            user: Duration::ZERO,
            system: Duration::ZERO,
            total: Duration::ZERO,
        };

        for line in buf.lines() {
            let target;
            if line.starts_with("user_usec ") {
                target = &mut stat.user;
            } else if line.starts_with("system_usec ") {
                target = &mut stat.system;
            } else {
                continue;
            }

            let mut it = line.split_ascii_whitespace();
            it.next();
            *target = Duration::from_micros(
                it.next()
                    .context("Invalid cpu.stat format")?
                    .parse()
                    .context("Invalid cpu.stat format")?,
            );
        }

        stat.total = stat.user + stat.system;

        Ok(stat)
    }

    pub fn was_oom_killed(&self) -> Result<bool> {
        let mut buf = String::new();
        self.proc_cgroup_fd
            .open_file(format!("box-{}/memory.events", self.box_id))
            .context("Failed to open memory.events for reading")?
            .read_to_string(&mut buf)
            .context("Failed to read memory.events")?;

        let mut oom_kill: Option<usize> = None;
        for line in buf.lines() {
            if line.starts_with("oom_kill ") {
                // oom_group_kill is not supported on some kernels
                let mut it = line.split_ascii_whitespace();
                it.next();
                oom_kill = Some(
                    it.next()
                        .context("Invalid memory.events format")?
                        .parse()
                        .context("Invalid memory.events format")?,
                );
            }
        }

        let oom_kill = oom_kill.context("oom_kill is missing from memory.events")?;
        Ok(oom_kill > 0)
    }

    fn _destroy(&mut self) -> Result<()> {
        self.dropped = true;
        self.kill_processes()?;
        remove_cgroup(
            &self.proc_cgroup_fd,
            format!("box-{}", self.box_id).as_ref(),
        )
        .context("Failed to remove user cgroup")?;
        Ok(())
    }

    pub fn destroy(mut self) -> Result<()> {
        self._destroy()
    }
}

impl Drop for UserCgroup {
    fn drop(&mut self) {
        if !self.dropped {
            if let Err(e) = self._destroy() {
                eprintln!("Error in Drop: {e:?}");
            }
        }
    }
}

pub fn revert_core_isolation(core: u64) -> Result<()> {
    remove_cgroup(
        &openat::Dir::open("/sys/fs/cgroup").context("Failed to open /sys/fs/cgroup")?,
        format!("sunwalker-box-core-{core}").as_ref(),
    )
}

fn chown_cgroup(dir: &openat::Dir, uid: Option<u32>, gid: Option<u32>) -> Result<()> {
    let uid = uid.map(|uid| nix::unistd::Uid::from_raw(uid));
    let gid = gid.map(|gid| nix::unistd::Gid::from_raw(gid));
    nix::unistd::fchown(dir.as_raw_fd(), uid, gid)
        .with_context(|| format!("Failed to chown <cgroup>"))?;
    for name in ["cgroup.procs", "cgroup.kill", "cpu.stat", "memory.max"] {
        nix::unistd::fchownat(
            Some(dir.as_raw_fd()),
            name,
            uid,
            gid,
            nix::unistd::FchownatFlags::NoFollowSymlink,
        )
        .with_context(|| format!("Failed to chown <cgroup>/{name}"))?;
    }
    Ok(())
}

fn remove_cgroup(parent: &openat::Dir, dir_name: &OsStr) -> Result<()> {
    let dir = parent
        .sub_dir(dir_name)
        .with_context(|| format!("Failed to open {dir_name:?}"))?;
    for entry in dir.list_dir(".").context("Failed to list directory")? {
        // list_self() is broken
        let entry = entry.context("Failed to list directory")?;
        if let Some(openat::SimpleType::Dir) = entry.simple_type() {
            remove_cgroup(&dir, entry.file_name())?;
        }
    }

    let mut backoff = std::time::Duration::from_millis(50);
    let mut times = 0;
    while let Err(e) = nix::unistd::unlinkat(
        Some(parent.as_raw_fd()),
        dir_name,
        nix::unistd::UnlinkatFlags::RemoveDir,
    ) {
        // cgroup operations are asynchronous, so deleting a cgroup right after killing children may
        // yield EBUSY
        if e == nix::errno::Errno::EBUSY && times < 5 {
            std::thread::sleep(backoff);
            backoff *= 2;
            times += 1;
        } else {
            return Err(e).with_context(|| format!("Failed to rmdir {dir_name:?}"))?;
        }
    }

    Ok(())
}

#[derive(Clone, Copy)]
pub struct CpuStats {
    pub user: Duration,
    pub system: Duration,
    pub total: Duration,
}
