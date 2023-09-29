use crate::{
    linux::{ids, openat::OpenAtDir},
    log,
};
use anyhow::{ensure, Context, Result};
use crossmist::Object;
use nix::libc::pid_t;
use rand::Rng;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::io::AsRawFd;
use std::time::Duration;

#[derive(Object)]
pub struct Cgroup {
    core_cgroup_fd: OpenAtDir,
}

#[derive(Object)]
pub struct ProcCgroup {
    core_cgroup_fd: OpenAtDir,
    id: String,
}

pub struct BoxCgroup {
    proc_cgroup_fd: OpenAtDir,
    box_id: String,
    dropped: bool,
}

impl Cgroup {
    pub fn new(core: u64) -> Result<Self> {
        log!("Creating cgroup");

        // Enabling controllers globally is necessary on some systems, e.g. WSL
        std::fs::write(
            "/sys/fs/cgroup/cgroup.subtree_control",
            "+cpu +cpuset +memory +pids",
        )
        .context("Failed to enable cgroup controllers")?;

        // Create a cgroup for the core; it must be an immediate child of the root cgroup
        let dir = format!("/sys/fs/cgroup/sunwalker-box-core-{core}");
        std::fs::create_dir_all(&dir).with_context(|| format!("Failed to mkdir {dir}"))?;
        std::fs::write(
            format!("{dir}/cgroup.subtree_control"),
            "+cpu +memory +pids",
        )
        .context("Failed to enable cgroup controllers")?;

        // sysfs is unavailable inside the box, so we have to acquire a file descriptor
        let core_cgroup_fd = OpenAtDir::open(&dir).context("Failed to open cgroup directory")?;

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

        Ok(Self { core_cgroup_fd })
    }

    pub fn add_self_as_manager(&self) -> Result<()> {
        self.core_cgroup_fd
            .write_file("manager/cgroup.procs", 0o700)
            .context("Failed to open cgroup.procs for writing")?
            .write(b"0\n")
            .context("Failed to move process")?;
        Ok(())
    }

    pub fn create_proc_cgroup(&self) -> Result<ProcCgroup> {
        let mut rng = rand::thread_rng();
        let id: String = (0..10)
            .map(|_| rng.sample(rand::distributions::Alphanumeric) as char)
            .collect();

        log!("Creating per-sandbox cgroup #{id}");

        self.core_cgroup_fd
            .create_dir(format!("proc-{id}"), 0o700)
            .with_context(|| format!("Failed to mkdir proc-{id}"))?;

        self.core_cgroup_fd
            .write_file(format!("proc-{id}/cgroup.subtree_control"), 0o700)
            .with_context(|| {
                format!("Failed to open proc-{id}/cgroup.subtree_control for writing")
            })?
            .write(b"+cpu +memory +pids\n")
            .context("Failed to enable cgroup controllers")?;

        nix::unistd::fchownat::<str>(
            Some(self.core_cgroup_fd.as_raw_fd()),
            &format!("proc-{id}"),
            Some(nix::unistd::Uid::from_raw(ids::EXTERNAL_ROOT_UID)),
            Some(nix::unistd::Gid::from_raw(ids::EXTERNAL_ROOT_GID)),
            nix::unistd::FchownatFlags::NoFollowSymlink,
        )
        .context("Failed to chown <cgroup>")?;

        Ok(ProcCgroup {
            core_cgroup_fd: self.core_cgroup_fd.try_clone()?,
            id,
        })
    }
}

impl ProcCgroup {
    pub fn create_box_cgroup(&self) -> Result<BoxCgroup> {
        // As several boxes may share a core, we can't use a fixed cgroup name
        let mut rng = rand::thread_rng();
        let box_id: String = (0..10)
            .map(|_| rng.sample(rand::distributions::Alphanumeric) as char)
            .collect();

        let box_dir = format!("proc-{}/box-{box_id}", self.id);
        self.core_cgroup_fd
            .create_dir(&box_dir, 0o700)
            .with_context(|| format!("Failed to mkdir {box_dir}"))?;

        Ok(BoxCgroup {
            proc_cgroup_fd: self
                .core_cgroup_fd
                .sub_dir(format!("proc-{}", self.id))
                .with_context(|| format!("Failed to open proc-{}", self.id))?,
            box_id,
            dropped: false,
        })
    }

    pub fn destroy(self) -> Result<()> {
        remove_cgroup(&self.core_cgroup_fd, format!("proc-{}", self.id).as_ref())
    }

    pub fn try_clone(&self) -> Result<Self> {
        Ok(ProcCgroup {
            core_cgroup_fd: self.core_cgroup_fd.try_clone()?,
            id: self.id.clone(),
        })
    }
}

impl BoxCgroup {
    pub fn add_process(&self, pid: pid_t) -> Result<()> {
        self.proc_cgroup_fd
            .write_file(format!("box-{}/cgroup.procs", self.box_id), 0o700)
            .context("Failed to open cgroup.procs for writing")?
            .write(format!("{pid}\n").as_ref())
            .context("Failed to move process")?;
        Ok(())
    }

    pub fn set_memory_limit(&self, limit: usize) -> Result<()> {
        self.proc_cgroup_fd
            .write_file(format!("box-{}/memory.max", self.box_id), 0o700)
            .context("Failed to open memory.max for writing")?
            .write(format!("{limit}\n").as_ref())
            .context("Failed to set memory limit")?;
        self.proc_cgroup_fd
            .write_file(format!("box-{}/memory.swap.max", self.box_id), 0o700)
            .context("Failed to open memory.swap.max for writing")?
            .write(b"0\n")
            .context("Failed to disable swap")?;
        self.proc_cgroup_fd
            .write_file(format!("box-{}/memory.oom.group", self.box_id), 0o700)
            .context("Failed to open memory.oom.group for writing")?
            .write(b"1\n")
            .context("Failed to enable OOM grouping")?;
        Ok(())
    }

    pub fn set_processes_limit(&self, limit: usize) -> Result<()> {
        self.proc_cgroup_fd
            .write_file(format!("box-{}/pids.max", self.box_id), 0o700)
            .context("Failed to open pids.max for writing")?
            .write(format!("{limit}\n").as_ref())
            .context("Failed to set processes limit")?;
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

    pub fn get_memory_peak(&self) -> Result<usize> {
        let mut buf = String::new();
        self.proc_cgroup_fd
            .open_file(format!("box-{}/memory.peak", self.box_id))
            .context("Failed to open memory.peak for reading")?
            .read_to_string(&mut buf)
            .context("Failed to read memory.peak")?;
        buf.trim().parse().context("Invalid memory.peak format")
    }

    pub fn get_memory_stats(&self) -> Result<MemoryStats> {
        let mut buf = String::new();
        self.proc_cgroup_fd
            .open_file(format!("box-{}/memory.stat", self.box_id))
            .context("Failed to open memory.stat for reading")?
            .read_to_string(&mut buf)
            .context("Failed to read memory.stat")?;

        let mut stat = MemoryStats {
            anon: 0,
            file: 0,
            kernel: 0,
            shmem: 0,
        };

        for line in buf.lines() {
            let target;
            if line.starts_with("anon ") {
                target = &mut stat.anon;
            } else if line.starts_with("file ") {
                target = &mut stat.file;
            } else if line.starts_with("kernel ") {
                target = &mut stat.kernel;
            } else if line.starts_with("shmem ") {
                target = &mut stat.shmem;
            } else {
                continue;
            }

            let mut it = line.split_ascii_whitespace();
            it.next();
            *target = it
                .next()
                .context("Invalid memory.stat format")?
                .parse()
                .context("Invalid memory.stat format")?;
        }

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

    pub fn get_current_processes(&self) -> Result<usize> {
        let mut buf = String::new();
        self.proc_cgroup_fd
            .open_file(format!("box-{}/cgroup.procs", self.box_id))
            .context("Failed to open cgroup.procs for reading")?
            .read_to_string(&mut buf)
            .context("Failed to read cgroup.procs")?;
        Ok(buf.lines().count())
    }

    fn _destroy(&mut self) -> Result<()> {
        self.dropped = true;
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

    pub fn kill(&mut self) -> Result<()> {
        kill_cgroup(
            &self.proc_cgroup_fd,
            format!("box-{}", self.box_id).as_ref(),
        )
        .context("Failed to kill user cgroup")
    }
}

impl Drop for BoxCgroup {
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
        &OpenAtDir::open("/sys/fs/cgroup").context("Failed to open /sys/fs/cgroup")?,
        format!("sunwalker-box-core-{core}").as_ref(),
    )
}

fn chown_cgroup(dir: &OpenAtDir, uid: Option<u32>, gid: Option<u32>) -> Result<()> {
    let uid = uid.map(nix::unistd::Uid::from_raw);
    let gid = gid.map(nix::unistd::Gid::from_raw);
    nix::unistd::fchownat(
        Some(dir.as_raw_fd()),
        ".",
        uid,
        gid,
        nix::unistd::FchownatFlags::NoFollowSymlink,
    )
    .context("Failed to chown <cgroup>")?;
    for name in [
        "cgroup.freeze",
        "cgroup.kill",
        "cgroup.procs",
        "cpu.stat",
        "memory.events",
        "memory.max",
        "memory.oom.group",
        "memory.peak",
        "memory.stat",
        "memory.swap.max",
    ] {
        if let Err(e) = nix::unistd::fchownat(
            Some(dir.as_raw_fd()),
            name,
            uid,
            gid,
            nix::unistd::FchownatFlags::NoFollowSymlink,
        ) {
            // We don't use some of the files on older kernels if they are unavailable
            if e != nix::errno::Errno::ENOENT {
                return Err(e).with_context(|| format!("Failed to chown <cgroup>/{name}"));
            }
        }
    }
    Ok(())
}

// This function is subject to race conditions because one cgroup can be removed by several
// processes simultaneously. Therefore, ENOENT is not considered an error.
fn remove_cgroup(parent: &OpenAtDir, dir_name: &str) -> Result<()> {
    kill_cgroup(parent, dir_name).with_context(|| format!("Failed to kill cgroup {dir_name}"))?;

    let dir = match parent.sub_dir(dir_name) {
        Ok(dir) => dir,
        Err(e) => {
            if e.kind() == std::io::ErrorKind::NotFound {
                return Ok(());
            }
            return Err(e).with_context(|| format!("Failed to open {dir_name:?}"));
        }
    };

    for entry in dir.list_dir(".").context("Failed to list directory")? {
        // list_self() is broken
        let entry = entry.context("Failed to list directory")?;
        if let Some(openat::SimpleType::Dir) = entry.simple_type() {
            remove_cgroup(
                &dir,
                entry.file_name().to_str().context("Invalid cgroup name")?,
            )?;
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
        if e == nix::errno::Errno::ENOENT {
            break;
        } else if e == nix::errno::Errno::EBUSY && times < 5 {
            log!("Could not delete {dir_name} immediately, sleeping for {backoff:?}");
            std::thread::sleep(backoff);
            backoff *= 2;
            times += 1;
        } else {
            return Err(e).with_context(|| format!("Failed to rmdir {dir_name:?}"));
        }
    }

    log!("Deleted {dir_name} successfully");
    Ok(())
}

fn kill_cgroup(parent: &OpenAtDir, dir_name: &str) -> Result<()> {
    // cgroup.kill is unavailable on older kernels
    match parent.write_file(format!("{dir_name}/cgroup.kill"), 0o700) {
        Ok(mut file) => {
            file.write(b"1\n").context("Failed to kill cgroup")?;
            return Ok(());
        }
        Err(e) => {
            if e.kind() != std::io::ErrorKind::NotFound
                && e.kind() != std::io::ErrorKind::PermissionDenied
            {
                return Err(e)
                    .with_context(|| format!("Failed to open {dir_name}/cgroup.kill for writing"));
            }
        }
    }

    parent
        .write_file(format!("{dir_name}/cgroup.freeze"), 0o700)
        .context("Failed to open cgroup.freeze for writing")?
        .write(b"1\n")
        .context("Failed to freeze cgroup")?;

    for line in BufReader::new(
        parent
            .open_file(format!("{dir_name}/cgroup.procs"))
            .context("Failed to open cgroup.procs for reading")?,
    )
    .lines()
    {
        let line = line.context("Failed to enumerate cgroup processes")?;
        let pid: pid_t = line.parse().context("Invalid cgroup.procs format")?;
        ensure!(
            pid > 0,
            "Found process from another pid namespace in cgroup.procs"
        );
        nix::sys::signal::kill(
            nix::unistd::Pid::from_raw(pid),
            nix::sys::signal::Signal::SIGKILL,
        )
        .context("Failed to kill process")?;
    }

    Ok(())
}

#[derive(Clone, Copy)]
pub struct CpuStats {
    pub user: Duration,
    pub system: Duration,
    pub total: Duration,
}

#[derive(Clone, Copy)]
pub struct MemoryStats {
    pub anon: usize,
    pub file: usize,
    pub kernel: usize,
    pub shmem: usize,
}
