use crate::{
    entry,
    linux::{cgroups, manager, mountns, procs, reaper, rootfs, sandbox, system},
};
use anyhow::{anyhow, bail, Context, Result};
use nix::{libc, libc::SYS_pidfd_open, sys::signal, unistd::Pid};
use std::os::fd::{FromRawFd, OwnedFd, RawFd};
use std::path::{Path, PathBuf};
use std::sync::mpsc;

pub struct Controller {
    quotas: rootfs::DiskQuotas,
    cgroup: Option<cgroups::Cgroup>,
    reaper_pid: Option<Pid>,
    reaper_channel: Option<
        multiprocessing::Duplex<reaper::Command, std::result::Result<Option<String>, String>>,
    >,
    manager_channel: Option<
        multiprocessing::Duplex<manager::Command, std::result::Result<Option<String>, String>>,
    >,
    rootfs_state: Option<rootfs::RootfsState>,
}

impl Controller {
    pub fn try_new(quotas: rootfs::DiskQuotas) -> Result<Self> {
        // Isolate various non-important namespaces
        sandbox::unshare_persistent_namespaces()
            .context("Failed to unshare persistent namespaces")?;

        Ok(Self {
            quotas,
            cgroup: None,
            reaper_pid: None,
            reaper_channel: None,
            manager_channel: None,
            rootfs_state: None,
        })
    }

    pub fn join_core(&mut self, core: u64) -> Result<()> {
        let cgroup = cgroups::Cgroup::new(core).context("Failed to create cgroup")?;

        // Move self to the right core so that spawning processes on the right core is fast. This also
        // has to be done before unsharing userns, as we'd then lose our root privileges, and moving
        // process from cgroup A to cgroup B requires write privileges in cgroup LCA(A, B), and if we
        // don't do it now, we won't be able to do it later.
        cgroup
            .add_self_as_manager()
            .context("Failed to add self to manager cgroup")?;

        self.cgroup = Some(cgroup);

        Ok(())
    }

    pub fn enter_root(&mut self, root: &Path) -> Result<()> {
        let root = std::fs::canonicalize(root).context("Failed to resolve path to root")?;

        // Do whatever cannot be done inside the userns. This mostly amounts to mounting stuff.
        // Create an isolated mountns for a dedicated /tmp/sunwalker_box directory
        mountns::unshare_mountns().context("Failed to unshare mount namespace")?;
        // Ensure our working area is ours only
        system::change_propagation("/", system::MS_PRIVATE | system::MS_REC)
            .context("Failed to change propagation to private")?;
        // Create the dedicated /tmp/sunwalker_box
        sandbox::enter_working_area().context("Failed to enter working area")?;
        // Create a copy of /dev
        sandbox::create_dev_copy().context("Failed to create /dev copy")?;

        // Setup rootfs
        let mut root_cur = PathBuf::from("/oldroot");
        root_cur.extend(root.strip_prefix("/"));
        self.rootfs_state =
            Some(rootfs::create_rootfs(&root_cur).context("Failed to create rootfs")?);

        Ok(())
    }

    pub fn apply_environment(&self, env: &[(String, String)]) {
        for (key, _) in std::env::vars_os() {
            std::env::remove_var(key);
        }
        std::env::set_var(
            "LD_LIBRARY_PATH",
            "/usr/local/lib64:/usr/local/lib:/usr/lib64:/usr/lib:/lib64:/lib",
        );
        std::env::set_var("LANGUAGE", "en_US");
        std::env::set_var("LC_ALL", "en_US.UTF-8");
        std::env::set_var("LC_ADDRESS", "en_US.UTF-8");
        std::env::set_var("LC_NAME", "en_US.UTF-8");
        std::env::set_var("LC_MONETARY", "en_US.UTF-8");
        std::env::set_var("LC_PAPER", "en_US.UTF-8");
        std::env::set_var("LC_IDENTIFIER", "en_US.UTF-8");
        std::env::set_var("LC_TELEPHONE", "en_US.UTF-8");
        std::env::set_var("LC_MEASUREMENT", "en_US.UTF-8");
        std::env::set_var("LC_TIME", "en_US.UTF-8");
        std::env::set_var("LC_NUMERIC", "en_US.UTF-8");
        std::env::set_var("LANG", "en_US.UTF-8");
        for (key, value) in env {
            std::env::set_var(key, value);
        }
    }

    pub fn start(&mut self, cli_command: entry::CLIStartCommand) -> Result<()> {
        // We need a separate worker to monitor the child (and no, using tokio won't work because then
        // using stdio would require a dedicated thread), but threads can't be created after unsharing
        // pidns, so we create the thread beforehand.
        let (thread_tx, thread_rx) = mpsc::channel();
        std::thread::spawn(move || {
            let mut child: multiprocessing::Child<!> =
                thread_rx.recv().expect("Failed to receive child in thread");
            panic!("Child failed: {}", child.join().into_err());
        });

        let (reaper_ours, reaper_theirs) = multiprocessing::duplex::<
            reaper::Command,
            std::result::Result<Option<String>, String>,
        >()
        .context("Failed to create channel")?;

        let (mut manager_ours, manager_theirs) = multiprocessing::duplex::<
            manager::Command,
            std::result::Result<Option<String>, String>,
        >()
        .context("Failed to create channel")?;

        // Run a child in a new PID namespace
        procs::unshare_pidns().context("Failed to unshare pid namespace")?;

        // We need to pass a reference to ourselves to the child for monitoring, but cross-pid-namespace
        // communication doesn't work well, so we use pidfd. As a side note, pidfd_open sets O_CLOEXEC
        // automatically.
        let pidfd = unsafe { libc::syscall(SYS_pidfd_open, nix::unistd::getpid(), 0) } as RawFd;
        if pidfd == -1 {
            panic!(
                "Failed to get pidfd of self: {}",
                std::io::Error::last_os_error()
            );
        }
        let pidfd = unsafe { OwnedFd::from_raw_fd(pidfd) };

        let cgroup = self
            .cgroup
            .take()
            .context("The controller has not joined a core cgroup yet")?;

        let child = reaper::reaper
            .spawn(pidfd, cli_command, cgroup, reaper_theirs, manager_theirs)
            .context("Failed to start child")?;
        self.reaper_pid = Some(Pid::from_raw(child.id()));
        thread_tx
            .send(child)
            .context("Failed to send child to thread")?;

        manager_ours
            .recv()
            .context("Failed to recv readiness signal")?
            .context("Manager terminated too early")?
            .map_err(|e| anyhow!("Manager reported error during startup: {e}"))?;

        self.reaper_channel = Some(reaper_ours);
        self.manager_channel = Some(manager_ours);

        // It's a bit weird, but there's stuff that's slightly wrong after initialization, like
        // pidns in an uncertain state or (more importantly) non-existent rootfs.
        self.reset()?;

        Ok(())
    }

    pub fn ensure_allowed_to_modify(&self, path: &Path) -> Result<()> {
        if path.components().count() == 3 {
            // /root/*
            bail!("File {path:?} cannot be modified");
        }
        Ok(())
    }

    pub fn reset(&mut self) -> Result<()> {
        sandbox::reset_persistent_namespaces().context("Failed to persistent namespaces")?;
        rootfs::reset(
            self.rootfs_state.as_mut().context("Did not join a core")?,
            &self.quotas,
        )
        .context("Failed to reset rootfs")?;

        // TODO: timens & rdtsc

        self.run_reaper_command(reaper::Command::Reset)?;
        Ok(())
    }

    pub fn bind(&mut self, external: &str, internal: &str, ro: bool) -> Result<()> {
        system::bind_mount(
            rootfs::resolve_abs_old_root(external)?,
            rootfs::resolve_abs_box_root(internal)?,
        )?;
        if ro {
            self.run_manager_command(manager::Command::RemountReadonly {
                path: internal.to_string(),
            })?;
        }
        Ok(())
    }

    pub fn run_reaper_command(&mut self, command: reaper::Command) -> Result<Option<String>> {
        let channel = self.reaper_channel.as_mut().context("Not started")?;

        channel.send(&command).context("Failed to send command")?;

        signal::kill(self.reaper_pid.expect("Not started"), signal::Signal::SIGIO)?;

        match channel.recv().context("Failed to recv reply")? {
            None => bail!("No reply from child"),
            Some(Ok(value)) => Ok(value),
            Some(Err(e)) => bail!("{e}"),
        }
    }

    pub fn run_manager_command(&mut self, command: manager::Command) -> Result<Option<String>> {
        let channel = self.manager_channel.as_mut().context("Not started")?;

        channel.send(&command).context("Failed to send command")?;

        match channel.recv().context("Failed to recv reply")? {
            None => bail!("No reply from child"),
            Some(Ok(value)) => Ok(value),
            Some(Err(e)) => bail!("{e}"),
        }
    }
}
