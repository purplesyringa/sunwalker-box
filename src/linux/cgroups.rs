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
    core: u64,
}

#[derive(Object)]
pub struct ProcCgroup {
    core_cgroup_fd: OpenAtDir,
    proc_cgroup_fd: OpenAtDir,
    proc_id: String,
}

pub struct BoxCgroup {
    proc_cgroup_fd: OpenAtDir,
    box_cgroup_fd: OpenAtDir,
    box_id: String,
    dropped: bool,
}

impl Cgroup {
    pub fn new(core: u64) -> Result<Self> {
        log!("Creating cgroup");

        // Create a cgroup for the core; it must be an immediate child of the root cgroup
        let dir = format!("/sys/fs/cgroup/sunwalker-box-core-{core}");
        std::fs::create_dir_all(&dir).with_context(|| format!("Failed to mkdir {dir}"))?;

        // sysfs is unavailable inside the box, so we have to acquire a file descriptor
        let core_cgroup_fd = OpenAtDir::open(&dir).context("Failed to open cgroup directory")?;
        chown_cgroup(
            &core_cgroup_fd,
            Some(ids::EXTERNAL_ROOT_UID),
            Some(ids::EXTERNAL_ROOT_GID),
        )
        .with_context(|| format!("Failed to chown {dir}"))?;

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

        Ok(Self {
            core_cgroup_fd,
            core,
        })
    }

    pub fn add_self_as_manager(&self) -> Result<()> {
        self.core_cgroup_fd
            .write_file("manager/cgroup.procs", 0o700)
            .context("Failed to open cgroup.procs for writing")?
            .write(b"0\n")
            .context("Failed to move process")?;
        Ok(())
    }

    pub fn enable_controllers(&self) -> Result<()> {
        // Write to cgroup.subtree_control *after* moving the manager to a subgroup. This way, we
        // handle Docker containers gracefully. Docker starts with one "root" cgroup with ourselves
        // as the process. Due to a quirk in Linux kernel, non-root cgroups can either contain
        // direct processes or have controllers enabled, but not both. Docker's "root" cgroup is not
        // a root cgroup for Linux, so this limitation is established, meaning that we have to
        // first move ourselves to a subgroup and then to enable controllers.

        // Enabling controllers globally is necessary on some systems, e.g. WSL
        std::fs::write(
            "/sys/fs/cgroup/cgroup.subtree_control",
            "+cpu +cpuset +memory +pids",
        )
        .context("Failed to enable cgroup controllers")?;

        // For core
        self.core_cgroup_fd
            .write_file("cgroup.subtree_control", 0o700)
            .context("Failed to open cgroup.subtree_control for writing")?
            .write(b"+cpu +memory +pids\n")
            .context("Failed to enable cgroup controllers")?;

        // Set core
        self.core_cgroup_fd
            .write_file("cpuset.cpus", 0o700)
            .context("Failed to open cpuset.cpus for writing")?
            .write(format!("{}", self.core).as_bytes())
            .context("Failed to set CPU")?;
        self.core_cgroup_fd
            .write_file("cpuset.cpus.partition", 0o700)
            .context("Failed to open cpuset.cpus.partition for writing")?
            .write(b"root")
            .context("Failed to switch partition type to 'root'")?;

        Ok(())
    }

    pub fn create_proc_cgroup(&self) -> Result<ProcCgroup> {
        let mut rng = rand::thread_rng();
        let proc_id: String = (0..10)
            .map(|_| rng.sample(rand::distributions::Alphanumeric) as char)
            .collect();
        let proc_id = format!("proc-{proc_id}");

        log!("Creating per-sandbox cgroup #{proc_id}");

        self.core_cgroup_fd
            .create_dir(&proc_id, 0o700)
            .with_context(|| format!("Failed to mkdir {proc_id}"))?;

        let proc_cgroup_fd = self
            .core_cgroup_fd
            .sub_dir(&proc_id)
            .with_context(|| format!("Failed to open {proc_id}"))?;

        proc_cgroup_fd
            .write_file("cgroup.subtree_control", 0o700)
            .with_context(|| {
                format!("Failed to open {proc_id}/cgroup.subtree_control for writing")
            })?
            .write(b"+cpu +memory +pids\n")
            .context("Failed to enable cgroup controllers")?;

        nix::unistd::fchownat::<str>(
            Some(self.core_cgroup_fd.as_raw_fd()),
            &proc_id,
            Some(nix::unistd::Uid::from_raw(ids::EXTERNAL_ROOT_UID)),
            Some(nix::unistd::Gid::from_raw(ids::EXTERNAL_ROOT_GID)),
            nix::unistd::FchownatFlags::NoFollowSymlink,
        )
        .context("Failed to chown <cgroup>")?;

        Ok(ProcCgroup {
            core_cgroup_fd: self.core_cgroup_fd.try_clone()?,
            proc_cgroup_fd,
            proc_id,
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
        let box_id = format!("box-{box_id}");

        self.proc_cgroup_fd
            .create_dir(&box_id, 0o700)
            .with_context(|| format!("Failed to mkdir {box_id} in {}", self.proc_id))?;

        let box_cgroup_fd = self
            .proc_cgroup_fd
            .sub_dir(&box_id)
            .with_context(|| format!("Failed to open {box_id} in {}", self.proc_id))?;

        Ok(BoxCgroup {
            proc_cgroup_fd: self.proc_cgroup_fd.try_clone()?,
            box_cgroup_fd,
            box_id,
            dropped: false,
        })
    }

    pub fn destroy(self) -> Result<()> {
        remove_cgroup(&self.core_cgroup_fd, &self.proc_id)
    }

    pub fn try_clone(&self) -> Result<Self> {
        Ok(ProcCgroup {
            core_cgroup_fd: self.core_cgroup_fd.try_clone()?,
            proc_cgroup_fd: self.proc_cgroup_fd.try_clone()?,
            proc_id: self.proc_id.clone(),
        })
    }
}

impl BoxCgroup {
    pub fn add_process(&self, pid: pid_t) -> Result<()> {
        self.box_cgroup_fd
            .write_file("cgroup.procs", 0o700)
            .context("Failed to open cgroup.procs for writing")?
            .write(format!("{pid}\n").as_ref())
            .context("Failed to move process")?;
        Ok(())
    }

    pub fn set_memory_limit(&self, limit: usize) -> Result<()> {
        self.box_cgroup_fd
            .write_file("memory.max", 0o700)
            .context("Failed to open memory.max for writing")?
            .write(format!("{limit}\n").as_ref())
            .context("Failed to set memory limit")?;
        self.box_cgroup_fd
            .write_file("memory.swap.max", 0o700)
            .context("Failed to open memory.swap.max for writing")?
            .write(b"0\n")
            .context("Failed to disable swap")?;
        self.box_cgroup_fd
            .write_file("memory.oom.group", 0o700)
            .context("Failed to open memory.oom.group for writing")?
            .write(b"1\n")
            .context("Failed to enable OOM grouping")?;
        Ok(())
    }

    pub fn set_processes_limit(&self, limit: usize) -> Result<()> {
        self.box_cgroup_fd
            .write_file("pids.max", 0o700)
            .context("Failed to open pids.max for writing")?
            .write(format!("{limit}\n").as_ref())
            .context("Failed to set processes limit")?;
        Ok(())
    }

    pub fn get_cpu_time(&self) -> Result<Duration> {
        let mut buf = String::new();
        self.box_cgroup_fd
            .open_file("cpu.stat")
            .context("Failed to open cpu.stat for reading")?
            .read_to_string(&mut buf)
            .context("Failed to read cpu.stat")?;

        // Compute CPU time as usage_user + usage_system as opposed to usage_usec. The reason for
        // such a strange choice is that usage_usec also includes stolen time, which logically
        // shouldn't be time spent by user code.
        let mut user = None;
        let mut system = None;

        for line in buf.lines() {
            let target;
            if line.starts_with("user_usec ") {
                target = &mut user;
            } else if line.starts_with("system_usec ") {
                target = &mut system;
            } else {
                continue;
            }

            let mut it = line.split_ascii_whitespace();
            it.next();
            *target = Some(Duration::from_micros(
                it.next()
                    .context("Invalid cpu.stat format")?
                    .parse()
                    .context("Invalid cpu.stat format")?,
            ));
        }

        Ok(user.context("Missing user_usec field in cpu.stat")?
            + system.context("Missing system_usec field in cpu.stat")?)
    }

    pub fn get_memory_peak(&self) -> Result<usize> {
        let mut buf = String::new();
        self.box_cgroup_fd
            .open_file("memory.peak")
            .context("Failed to open memory.peak for reading")?
            .read_to_string(&mut buf)
            .context("Failed to read memory.peak")?;
        buf.trim().parse().context("Invalid memory.peak format")
    }

    pub fn get_memory_stats(&self) -> Result<MemoryStats> {
        let mut buf = String::new();
        self.box_cgroup_fd
            .open_file("memory.stat")
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
        self.box_cgroup_fd
            .open_file("memory.events")
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
        self.box_cgroup_fd
            .open_file("cgroup.procs")
            .context("Failed to open cgroup.procs for reading")?
            .read_to_string(&mut buf)
            .context("Failed to read cgroup.procs")?;
        Ok(buf.lines().count())
    }

    fn _destroy(&mut self) -> Result<()> {
        self.dropped = true;
        remove_cgroup(&self.proc_cgroup_fd, &self.box_id)
            .context("Failed to remove user cgroup")?;
        Ok(())
    }

    pub fn destroy(mut self) -> Result<()> {
        self._destroy()
    }

    pub fn kill(&mut self) -> Result<()> {
        kill_cgroup(&self.proc_cgroup_fd, &self.box_id).context("Failed to kill user cgroup")
    }
}

impl Drop for BoxCgroup {
    fn drop(&mut self) {
        if !self.dropped
            && let Err(e) = self._destroy() {
                eprintln!("Error in Drop: {e:?}");
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
    let dir = match parent.sub_dir(dir_name) {
        Ok(dir) => dir,
        Err(e) => {
            if e.kind() == std::io::ErrorKind::NotFound {
                return Ok(());
            }
            return Err(e).with_context(|| format!("Failed to open {dir_name:?}"));
        }
    };

    kill_cgroup(parent, dir_name).with_context(|| format!("Failed to kill cgroup {dir_name}"))?;

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
pub struct MemoryStats {
    pub anon: usize,
    pub file: usize,
    pub kernel: usize,
    pub shmem: usize,
}
