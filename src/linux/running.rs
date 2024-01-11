use crate::{
    linux::{cgroups, ipc, rootfs, string_table, system, timens, tracing, userns},
    log, syscall,
};
use anyhow::{bail, ensure, Context, Result};
use crossmist::Object;
use nix::{
    errno, libc,
    libc::pid_t,
    sched,
    sys::{epoll, ptrace, signal, signalfd, sysinfo, wait},
    unistd,
    unistd::Pid,
};
use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::ffi::{CString, OsStr};
use std::fs::File;
use std::io;
use std::mem::MaybeUninit;
use std::os::unix::{ffi::OsStrExt, fs::PermissionsExt, io::AsRawFd};
use std::time::{Duration, Instant};

pub struct Runner {
    proc_cgroup: cgroups::ProcCgroup,
    timens_controller: timens::TimeNsController,
    sigfd: signalfd::SignalFd,
    epoll: epoll::Epoll,
    exec_wrapper: File,
}

#[derive(Debug, Object)]
pub struct Options {
    pub argv: Vec<String>,
    pub stdin: String,
    pub stdout: String,
    pub stderr: String,
    pub real_time_limit: Option<Duration>,
    pub cpu_time_limit: Option<Duration>,
    pub idleness_time_limit: Option<Duration>,
    pub memory_limit: Option<usize>,
    pub processes_limit: Option<usize>,
    pub env: Option<HashMap<String, String>>,
}

#[derive(PartialEq, Eq)]
pub enum Verdict {
    ExitCode(i32),
    Signaled(i32),
    CPUTimeLimitExceeded,
    RealTimeLimitExceeded,
    IdlenessTimeLimitExceeded,
    MemoryLimitExceeded,
}

pub struct RunResults {
    pub verdict: Verdict,
    pub real_time: Duration,
    pub cpu_time: Duration,
    pub idleness_time: Duration,
    pub memory: usize,
}

#[derive(Debug, PartialEq, Eq)]
enum ProcessState {
    AwaitingForkNotification,
    JustStarted,
    Alive,
    AfterOpenMemfd(Vec<u8>),
}

struct ProcessInfo {
    state: ProcessState,
    traced_process: tracing::TracedProcess,
}

struct SingleRun<'a> {
    runner: &'a mut Runner,
    options: Options,
    results: RunResults,
    box_cgroup: Option<cgroups::BoxCgroup>,
    main_pid: Pid,
    start_time: Option<Instant>,
    processes: HashMap<Pid, RefCell<ProcessInfo>>,
    #[cfg(target_arch = "x86_64")]
    tsc_shift: u64,
    sem_next_id: Cell<isize>,
    msg_next_id: Cell<isize>,
    shm_next_id: Cell<isize>,
}

enum EmulatedSyscall {
    Result(usize),
    Redirect(tracing::SyscallArgs, ProcessState),
}

impl EmulatedSyscall {
    fn result_or_errno(mut result: usize) -> Self {
        if result == usize::MAX {
            result = -errno::errno() as usize;
        }
        Self::Result(result)
    }

    fn redirect_with_errno(result: io::Result<(tracing::SyscallArgs, ProcessState)>) -> Self {
        match result {
            Ok((args, state)) => Self::Redirect(args, state),
            Err(err) => Self::Result(-err.raw_os_error().unwrap_or(libc::EINVAL) as usize),
        }
    }
}

impl Runner {
    pub fn new(proc_cgroup: cgroups::ProcCgroup) -> Result<Self> {
        log!("Initializing runner");

        // Mount procfs and enter the sandboxed root
        let timens_controller = timens::TimeNsController::new().context("Failed to adjust time")?;
        rootfs::configure_rootfs().context("Failed to configure rootfs")?;
        userns::enter_user_namespace().context("Failed to unshare user namespace")?;
        rootfs::enter_rootfs().context("Failed to enter rootfs")?;

        // Unshare IPC namespace now, so that it is owned by the new userns and can be configured
        sched::unshare(sched::CloneFlags::CLONE_NEWIPC)
            .context("Failed to unshare IPC namespace")?;

        // Create signalfd to watch child's state change
        let mut sigset = signal::SigSet::empty();
        sigset.add(signal::Signal::SIGCHLD);
        sigset.thread_block().context("Failed to block SIGCHLD")?;
        let sigfd = signalfd::SignalFd::with_flags(
            &sigset,
            signalfd::SfdFlags::SFD_NONBLOCK | signalfd::SfdFlags::SFD_CLOEXEC,
        )
        .context("Failed to create signalfd")?;

        let epoll = epoll::Epoll::new(epoll::EpollCreateFlags::EPOLL_CLOEXEC)
            .context("Failed to create epoll")?;
        epoll
            .add(
                &sigfd,
                epoll::EpollEvent::new(epoll::EpollFlags::EPOLLIN, 0),
            )
            .context("Failed to configure epoll")?;

        let exec_wrapper = system::make_memfd(
            "exec_wrapper",
            include_bytes!("../../target/exec_wrapper.stripped"),
        )
        .context("Failed to create memfd for exec_wrapper")?;

        Ok(Runner {
            proc_cgroup,
            timens_controller,
            sigfd,
            epoll,
            exec_wrapper,
        })
    }

    pub fn run(&mut self, options: Options) -> Result<RunResults> {
        let mut single_run = SingleRun {
            runner: self,
            options,
            results: RunResults {
                verdict: Verdict::ExitCode(0),
                real_time: Duration::ZERO,
                cpu_time: Duration::ZERO,
                idleness_time: Duration::ZERO,
                memory: 0,
            },
            box_cgroup: None,
            main_pid: Pid::from_raw(0),
            start_time: None,
            processes: HashMap::new(),
            #[cfg(target_arch = "x86_64")]
            tsc_shift: rand::random::<u64>(),
            sem_next_id: Cell::new(0),
            msg_next_id: Cell::new(0),
            shm_next_id: Cell::new(0),
        };
        single_run.run()?;
        Ok(single_run.results)
    }
}

impl SingleRun<'_> {
    fn open_standard_streams(&self) -> Result<[File; 3]> {
        log!("Opening standard streams");

        let stdin = File::open(&self.options.stdin).context("Failed to open stdin file")?;
        let stdout = File::options()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&self.options.stdout)
            .context("Failed to open stdout file")?;
        let stderr = File::options()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&self.options.stderr)
            .context("Failed to open stderr file")?;
        Ok([stdin, stdout, stderr])
    }

    fn create_box_cgroup(&mut self) -> Result<()> {
        log!("Creating a per-run cgroup");
        let box_cgroup = self
            .runner
            .proc_cgroup
            .create_box_cgroup()
            .context("Failed to create user cgroup")?;
        if let Some(memory_limit) = self.options.memory_limit {
            box_cgroup
                .set_memory_limit(memory_limit)
                .context("Failed to apply memory limit")?;
        }
        if let Some(processes_limit) = self.options.processes_limit {
            box_cgroup
                .set_processes_limit(processes_limit)
                .context("Failed to apply processes limit")?;
        }
        self.box_cgroup = Some(box_cgroup);
        Ok(())
    }

    fn start_worker(&mut self) -> Result<tracing::TracedProcess> {
        let [stdin, stdout, stderr] = self.open_standard_streams()?;

        // Start process, redirecting standard streams and configuring ITIMER_PROF
        log!("Starting executor worker");
        let (theirs, mut ours) = crossmist::channel().context("Failed to create a pipe")?;
        let user_process = executor_worker
            .spawn(
                self.options.argv.clone(),
                self.options.env.clone(),
                stdin,
                stdout,
                stderr,
                theirs,
                self.runner
                    .exec_wrapper
                    .try_clone()
                    .context("Failed to clone exec_wrapper")?,
            )
            .context("Failed to spawn the child")?;
        self.main_pid = Pid::from_raw(user_process.id());

        // The child will either exit or trigger SIGTRAP on execve() to exec_wrapper due to ptrace
        let wait_status = system::waitpid(Some(self.main_pid), wait::WaitPidFlag::empty())
            .context("Failed to waitpid for process")?;
        log!("Worker has stopped on launch with {wait_status:?}");

        match wait_status {
            system::WaitStatus::Exited(_, _) => {
                bail!(
                    "{}",
                    ours.recv()
                        .context("Failed to read an error from the child")?
                        .context("The child terminated but did not report any error")?
                );
            }
            system::WaitStatus::Stopped(_, libc::SIGTRAP) => {}
            _ => {
                bail!("waitpid returned unexpected status: {wait_status:?}");
            }
        };

        // Apply cgroup limits
        self.create_box_cgroup()?;
        log!("Moving worker to cgroup");
        self.box_cgroup
            .as_mut()
            .unwrap()
            .add_process(self.main_pid.as_raw())
            .context("Failed to move the child to user cgroup")?;

        let mut traced_process = tracing::TracedProcess::new(self.main_pid)?;

        if let Some(cpu_time_limit) = self.options.cpu_time_limit {
            // An additional optimization for finer handling of cpu time limit. An ITIMER_PROF timer
            // can emit a signal when the given limit is exceeded and is not reset upon execve. This
            // only applies to a single process, not a cgroup, and can be overwritten by the user
            // program, but this feature is not mission-critical. It merely saves us a few precious
            // milliseconds due to the (somewhat artificially deliberate) inefficiency of polling.
            //
            // We set itimer after adding the process to the cgroup so that when SIGPROF fires, it
            // is guaranteed that the cgroup limit has indeed been exceeded.

            const EXEC_WRAPPER_ITIMER_VALUE: usize =
                include!("../../target/exec_wrapper.itimer_prof");
            let timeval = libc::timeval {
                tv_sec: cpu_time_limit.as_secs() as i64,
                tv_usec: cpu_time_limit.subsec_micros() as i64,
            };

            traced_process
                .write_memory(EXEC_WRAPPER_ITIMER_VALUE + 16, &unsafe {
                    std::mem::transmute::<libc::timeval, [u8; 16]>(timeval)
                })
                .context("Failed to write itimer_value to exec_wrapper memory")?;
        }

        // execve() the real program
        log!("Starting user process");
        traced_process.resume()?;

        // The child will either exit or trigger SIGTRAP on execve() to the real program
        let wait_status = system::waitpid(Some(self.main_pid), wait::WaitPidFlag::empty())
            .context("Failed to waitpid for process")?;
        log!("Worker has stopped on execve with {wait_status:?}");

        match wait_status {
            system::WaitStatus::Exited(_, exit_code) => {
                let errno = exit_code;
                bail!(
                    "Failed to start program with error {}",
                    std::io::Error::from_raw_os_error(errno)
                );
            }
            system::WaitStatus::Stopped(_, libc::SIGTRAP) => {
                traced_process.reload_mm()?;
                Ok(traced_process)
            }
            _ => {
                bail!("waitpid returned unexpected status: {wait_status:?}");
            }
        }
    }

    fn compute_wait_timeout_ms(&self) -> i32 {
        let mut timeout = Duration::MAX;

        if let Some(real_time_limit) = self.options.real_time_limit {
            timeout = timeout.min(real_time_limit - self.results.real_time);
        }

        // The connection between real time and CPU time is complicated. On the one hand, a process
        // can sleep, which does not count towards CPU time, so it can be as low as it gets.
        // Secondly, multithreaded applications can use several cores (TODO: add opt-in support for
        // that), and that means CPU time may exceed real time. The inequality seems to be
        //     0 <= cpu_time <= real_time * n_cores,
        // so a process cannot exceed its CPU time limit during
        //     cpu_time_left / n_cores
        // seconds. This gives us a better way to handle TLE than by polling the stats every few
        // milliseconds. Instead, the algorithm is roughly (other limits notwithstanding):
        //     while the process has not terminated and limits are not exceeded {
        //         let guaranteed_cpu_time_left = how much more CPU time the process can
        //             spend without exceeding the limit;
        //         let guaranteed_real_time_left = guaranteed_cpu_time_left / n_cores;
        //         sleep(guaranteed_real_time_left);
        //     }

        // Switching context takes time, some other operations take time too, etc., so less CPU time
        // is usually used than permitted. We also don't really want to interrupt the process. We
        // need to set a low limit on the timeout as well.
        //
        // In practice, adding 50ms seems like a good solution. This is not too big a number to slow
        // the judgment, not too small to steal resources from the solution in what is effectively a
        // spin lock, and allows SIGPROF to fire just at the right moment under normal
        // circumstances.
        if let Some(cpu_time_limit) = self.options.cpu_time_limit {
            timeout =
                timeout.min(cpu_time_limit - self.results.cpu_time + Duration::from_millis(50));
        }

        // Similarly, a process cannot exceed its idleness time limit during idleness_time_left
        // seconds. It is not obvious how idleness time is to interact with multicore programs, so
        // we should forbid the limit in this case (TODO).
        //
        // We add 50ms here too, because when little idleness time is left, the process might just
        // spend the rest of time crunching CPU cycles without spending idleness time.
        if let Some(idleness_time_limit) = self.options.idleness_time_limit {
            timeout = timeout
                .min(idleness_time_limit - self.results.idleness_time + Duration::from_millis(50));
        }

        if timeout == Duration::MAX {
            -1
        } else {
            timeout.as_millis().try_into().unwrap_or(i32::MAX)
        }
    }

    fn is_exceeding<T: PartialOrd>(limit: Option<T>, value: T) -> bool {
        limit.is_some_and(|limit| value > limit)
    }

    fn is_exceeding_limits(&self) -> bool {
        Self::is_exceeding(self.options.cpu_time_limit, self.results.cpu_time)
            || Self::is_exceeding(self.options.real_time_limit, self.results.real_time)
            || Self::is_exceeding(self.options.idleness_time_limit, self.results.idleness_time)
            || Self::is_exceeding(self.options.memory_limit, self.results.memory)
    }

    fn compute_verdict(&self, wait_status: system::WaitStatus) -> Result<Verdict> {
        if Self::is_exceeding(self.options.cpu_time_limit, self.results.cpu_time) {
            if let system::WaitStatus::Stopped(_, libc::SIGPROF) = wait_status {
            } else {
                log!(
                    warn,
                    "The user process has exceeded CPU time limit without triggering SIGPROF. \
                     This may be due to the process using itimers for something else -- if that \
                     is unexpected, consider reporting an inefficiency."
                );
            }
            return Ok(Verdict::CPUTimeLimitExceeded);
        } else if Self::is_exceeding(self.options.real_time_limit, self.results.real_time) {
            return Ok(Verdict::RealTimeLimitExceeded);
        } else if Self::is_exceeding(self.options.idleness_time_limit, self.results.idleness_time) {
            return Ok(Verdict::IdlenessTimeLimitExceeded);
        } else if self.box_cgroup.as_ref().unwrap().was_oom_killed()? {
            if !Self::is_exceeding(self.options.memory_limit, self.results.memory) {
                log!(
                    impossible,
                    "The user process has triggered OOM killer without exceeding memory limits. \
                     This is either indicates too high memory pressure, making the verdict \
                     horribly wrong by blaming the participant instead of the invoker, or means \
                     that the user attempted to allocate too much in one shot. Whether the latter
                     case is possible is up in the air: it seems like you can only populate one \
                     page at a time -- but if it is, please notify us."
                );
            }
            return Ok(Verdict::MemoryLimitExceeded);
        } else if Self::is_exceeding(self.options.memory_limit, self.results.memory) {
            log!(
                impossible,
                "The user process has exceeded memory limit without triggering OOM killer. This \
                 might indicate something has gone horribly wrong with cgroups, or a race \
                 condition. Either way, you need to figure this out."
            );
            return Ok(Verdict::MemoryLimitExceeded);
        }
        match wait_status {
            system::WaitStatus::Exited(_, exit_code) => Ok(Verdict::ExitCode(exit_code)),
            system::WaitStatus::Signaled(_, signal) => Ok(Verdict::Signaled(signal)),
            _ => bail!("waitpid returned unexpected status: {wait_status:?}"),
        }
    }

    fn wait_for_event(&mut self) -> Result<system::WaitStatus> {
        let timeout_ms = self.compute_wait_timeout_ms();

        if timeout_ms == -1 {
            // Wait for infinity
            return system::waitpid(None, system::WaitPidFlag::__WALL)
                .context("Failed to waitpid for process");
        }

        let wait_status = system::waitpid(
            None,
            system::WaitPidFlag::__WALL | system::WaitPidFlag::WNOHANG,
        )
        .context("Failed to waitpid for process")?;
        if wait_status != system::WaitStatus::StillAlive {
            return Ok(wait_status);
        }

        let mut events = [epoll::EpollEvent::empty()];
        let n_events = self
            .runner
            .epoll
            .wait(&mut events, timeout_ms as isize)
            .context("epoll_wait failed")?;

        match n_events {
            0 => Ok(system::WaitStatus::StillAlive),
            1 => {
                while self
                    .runner
                    .sigfd
                    .read_signal()
                    .context("Failed to read signal")?
                    .is_some()
                {}

                Ok(system::waitpid(
                    None,
                    system::WaitPidFlag::__WALL | system::WaitPidFlag::WNOHANG,
                )
                .context("Failed to waitpid for process")?)
            }
            _ => Err(std::io::Error::last_os_error())
                .with_context(|| format!("epoll_wait returned {n_events}")),
        }
    }

    fn update_metrics(&mut self) -> Result<()> {
        let cpu_stats = self.box_cgroup.as_mut().unwrap().get_cpu_stats()?;
        self.results.cpu_time = cpu_stats.total;
        self.results.real_time = self.start_time.unwrap().elapsed();
        self.results.idleness_time = self.results.real_time.saturating_sub(self.results.cpu_time);
        Ok(())
    }

    fn on_after_fork(&self, process: &mut ProcessInfo) -> Result<()> {
        log!(
            "Initializing process {} after fork",
            process.traced_process.get_pid()
        );
        process.traced_process.init()?;
        process.traced_process.resume()?;
        Ok(())
    }

    fn on_after_execve(&self, process: &mut ProcessInfo) -> Result<()> {
        log!(
            "Initializing process {} after execve",
            process.traced_process.get_pid()
        );
        // Required to make clock_gettime work, because it would otherwise rely on processor
        // features we disabled -- and we can't emulate them when IP is in vDSO
        process.traced_process.disable_vdso()?;
        Ok(())
    }

    fn on_seccomp(&self, process: &mut ProcessInfo) -> Result<()> {
        let pid = process.traced_process.get_pid();

        let syscall_info = process
            .traced_process
            .get_syscall_info()
            .context("Failed to get syscall info")?;
        let syscall_info = unsafe { syscall_info.u.seccomp };

        let syscall_args = tracing::SyscallArgs {
            syscall_no: syscall_info.nr as i32,
            args: syscall_info.args.map(|arg| arg as usize),
        };

        match self.emulate_syscall(process, syscall_info)? {
            EmulatedSyscall::Result(result) => {
                if result as isize >= 0 {
                    log!("Emulating <pid {pid}> {syscall_args} = {result}");
                } else {
                    log!(
                        "Emulating <pid {pid}> {syscall_args} = -{}",
                        string_table::errno_to_name(-(result as i32))
                    );
                }
                process.traced_process.set_syscall_result(result)?;
                process.traced_process.set_active_syscall_no(-1)?; // skip syscall
                process.state = ProcessState::Alive;
            }
            EmulatedSyscall::Redirect(args, state) => {
                log!("Emulating <pid {pid}> {syscall_args} -> {args} (redirect)");
                process.traced_process.set_syscall(args)?;
                process.state = state;
            }
        }

        if process.state == ProcessState::Alive {
            process.traced_process.resume()?;
        } else {
            process.traced_process.resume_syscall()?;
        }

        Ok(())
    }

    fn emulate_syscall(
        &self,
        process: &mut ProcessInfo,
        syscall_info: tracing::ptrace_syscall_info_seccomp,
    ) -> Result<EmulatedSyscall> {
        let set_next_id = |name, cell: &Cell<isize>| -> Result<()> {
            if ipc::get_next_id(name)? == -1 {
                let id = cell.get();
                ipc::set_next_id(name, id)?;
                cell.set(id + 1);
            }
            Ok(())
        };

        match syscall_info.nr as i64 {
            // We could theoretically let next_id stay 0 forever, but the present implementation
            // mirrors the original behavior and might be somewhat more efficient.
            //
            // We execute the syscall in this process rather than continue execution to prevent the
            // following TOCTOU attack:
            // - Process A calls msgget()
            // - Tracer intercepts msgget() and sets msg_next_id on behalf of A
            // - Process B SIGSTOPs A
            // - Tracer resumes A
            // - Process B calls msgget()
            // - Tracer intercepts msgget(), sets msg_next_id on behalf of B, and resumes B
            // - Process B executes the msgget() syscall, resetting msg_next_id to -1
            // - Process B SIGCONTs A
            // - Process A executes the msgget() syscall, but msg_next_id = -1 at the moment
            libc::SYS_semget => {
                set_next_id("sem", &self.sem_next_id)?;
                Ok(EmulatedSyscall::result_or_errno(unsafe {
                    libc::semget(
                        syscall_info.args[0] as i32,
                        syscall_info.args[1] as i32,
                        syscall_info.args[2] as i32,
                    ) as usize
                }))
            }
            libc::SYS_msgget => {
                set_next_id("msg", &self.msg_next_id)?;
                Ok(EmulatedSyscall::result_or_errno(unsafe {
                    libc::msgget(syscall_info.args[0] as i32, syscall_info.args[1] as i32) as usize
                }))
            }
            libc::SYS_shmget => {
                set_next_id("shm", &self.shm_next_id)?;
                Ok(EmulatedSyscall::result_or_errno(unsafe {
                    libc::shmget(
                        syscall_info.args[0] as i32,
                        syscall_info.args[1] as usize,
                        syscall_info.args[2] as i32,
                    ) as usize
                }))
            }
            libc::SYS_memfd_create => {
                Ok(EmulatedSyscall::redirect_with_errno(
                    try {
                        let mut open_flags = libc::O_RDWR;
                        if syscall_info.args[1] & (libc::MFD_CLOEXEC as u64) != 0 {
                            open_flags |= libc::O_CLOEXEC;
                        }
                        // TODO: sealing
                        if syscall_info.args[1]
                            & !(libc::MFD_CLOEXEC
                                | libc::MFD_HUGETLB
                                | (libc::MFD_HUGE_MASK << libc::MFD_HUGE_SHIFT))
                                as u64
                            != 0
                        {
                            Err(std::io::Error::from_raw_os_error(libc::EINVAL))?;
                        }

                        let mut name = process
                            .traced_process
                            .read_cstring(syscall_info.args[0] as usize, 249)?
                            .into_bytes();

                        // Sanitization
                        name.retain(|&c| c != b'/');

                        let mut path = Vec::from(b"/memfd:");
                        path.append(&mut name);

                        // This attempts to create a file named memfd:... in the root tmpfs. This
                        // ensures the path shown in /proc/.../maps matches the name memfd_create
                        // would generate unless the filename contains /. This can theoretically
                        // collide with an existing file in the chroot, but that would be rather
                        // stupid from the rootfs generator, and we believe our users are not
                        // morons.
                        let mut file = File::create_new(OsStr::from_bytes(&path));
                        if let Err(ref e) = file
                            && e.kind() == io::ErrorKind::AlreadyExists
                        {
                            // Either the chroot creator is, in fact, a moron, or some of our
                            // processes is in a racy "openat is just about to run" state.
                            log!(
                                warn,
                                "A file matching the pattern /memfd:... exists in the root \
                                 filesystem. This indicated either that a race condition in \
                                 memfd_create logic was triggered, or that such a file exists in \
                                 the chroot passed to sunwalker-box. In the former case, please \
                                 report this if it happens in the wild so that we can workaround \
                                 it or prioritize a proper fix. In the latter case, please remove \
                                 or rename the file."
                            );
                            // Assume the latter and rename the file to something random.
                            path = Vec::from(b"/memfd:fallback");
                            path.extend(rand::random::<u64>().to_string().as_bytes());
                            file = File::create_new(OsStr::from_bytes(&path));
                        }

                        // Any other error isn't supposed to happen under any condition.
                        if file.is_err() {
                            log!(
                                impossible,
                                "An attempt to create /memfd:... failed. This is a bug in \
                                 sunwalker-box."
                            );
                            Err(std::io::Error::from_raw_os_error(libc::ENOMEM))?;
                        }

                        if std::fs::set_permissions(
                            OsStr::from_bytes(&path),
                            PermissionsExt::from_mode(0o666),
                        )
                        .is_err()
                        {
                            log!(
                                impossible,
                                "An attempt to chmod /memfd:... failed. This is a bug in \
                                 sunwalker-box."
                            );
                            Err(std::io::Error::from_raw_os_error(libc::ENOMEM))?;
                        }

                        // Open the same path in the user process
                        path.push(b'\0');

                        // Account for red zone
                        let file_name_addr =
                            (process.traced_process.get_stack_pointer()? - 128) - path.len();

                        process.traced_process.write_memory(file_name_addr, &path)?;

                        // Note that files created in / are not accounted for by the tmpfs quotas.
                        // Therefore memfds are not subject to disk quotas, which are typically
                        // lower than the memory limit. This behavior has caused problems before,
                        // see e.g. https://github.com/purplesyringa/sunwalker-box/issues/7.
                        //
                        // However, these files *are* accounted for by the cgroup. Indeed, any
                        // attempt to write to the memfd (initially empty) by a user process will
                        // allocate pages, and shmem_alloc_and_add_folio charges the pages to the
                        // memory cgroup of the current process (see e.g.
                        // mm/shmem.c:mem_cgroup_charge:1679 on Linux v6.7.9). Therefore, memfd is
                        // effectively treated as an extension to RAM, which is what it is supposed
                        // to be anyway.

                        path.pop().unwrap();

                        (
                            syscall!(openat(AT_FDCWD, file_name_addr, open_flags, 0)),
                            ProcessState::AfterOpenMemfd(path),
                        )
                    },
                ))
            }
            libc::SYS_sysinfo => {
                let our_sysinfo = sysinfo::sysinfo().context("Failed to get sysinfo")?;

                // Don't leak sunwalker's memory in padding bytes
                let mut user_sysinfo = MaybeUninit::<libc::sysinfo>::zeroed();
                let user_sysinfo_mut = unsafe { user_sysinfo.assume_init_mut() };

                let mem = self
                    .box_cgroup
                    .as_ref()
                    .unwrap()
                    .get_memory_stats()
                    .context("Failed to get memory stats")?;

                user_sysinfo_mut.uptime = (our_sysinfo.uptime()
                    - Duration::from_secs(self.runner.timens_controller.get_uptime_shift()))
                .as_secs();
                user_sysinfo_mut.loads = [0; 3]; // there's no practical way to replicate LA
                if let Some(limit) = self.options.memory_limit {
                    user_sysinfo_mut.totalram = limit as u64;
                } else {
                    user_sysinfo_mut.totalram = our_sysinfo.ram_total();
                }
                user_sysinfo_mut.freeram =
                    user_sysinfo_mut.totalram - (mem.anon + mem.file + mem.kernel) as u64;
                user_sysinfo_mut.sharedram = mem.shmem as u64;
                user_sysinfo_mut.bufferram = mem.file as u64;
                user_sysinfo_mut.totalswap = 0;
                user_sysinfo_mut.freeswap = 0;
                user_sysinfo_mut.procs = self
                    .box_cgroup
                    .as_ref()
                    .unwrap()
                    .get_current_processes()
                    .context("Failed to get count of runnning processes")?
                    as u16;
                user_sysinfo_mut.totalhigh = 0;
                user_sysinfo_mut.freehigh = 0;
                user_sysinfo_mut.mem_unit = 1;

                if process
                    .traced_process
                    .write_memory(syscall_info.args[0] as usize, unsafe {
                        // We have to force the size to 112 bytes because musl's sysinfo is much
                        // larger, and we don't want to override user's data
                        MaybeUninit::slice_assume_init_ref(&user_sysinfo.as_bytes()[..112])
                    })
                    .is_ok()
                {
                    Ok(EmulatedSyscall::Result(0))
                } else {
                    Ok(EmulatedSyscall::Result(-libc::EFAULT as usize))
                }
            }
            _ => {
                log!(
                    impossible,
                    "An unexpected syscall was encountered. It was redirected to us via seccomp, \
                     which means that either we fucked up the politics, or the child process has \
                     set up its own seccomp rules with trace semantics. In the latter case, the \
                     program is utterly broken: if you set up seccomp and then trigger a syscall \
                     requiring tracing without checking that ptrace has returned an expected \
                     result, you're a basically asking for -ENOSYS. In the former case, well -- \
                     you need to report that."
                );
                Ok(EmulatedSyscall::Result(-libc::ENOSYS as usize))
            }
        }
    }

    #[cfg(target_arch = "x86_64")]
    fn handle_sigsegv(&self, process: &mut ProcessInfo) -> Result<()> {
        let info = process.traced_process.get_signal_info()?;
        // Excuse me?
        ensure!(
            info.si_signo == signal::Signal::SIGSEGV as i32,
            "This shouldn't happen: signal number mismatch between waitpid and PTRACE_GETSIGINFO"
        );

        if info.si_code == libc::SI_KERNEL {
            let fault_address = unsafe { info.si_addr() as usize };
            if fault_address == 0 && self.emulate_insn(process)? {
                return Ok(());
            }
        }

        log!("Delivering SIGSEGV");
        process.traced_process.resume_signal(libc::SIGSEGV)?;
        Ok(())
    }

    #[cfg(target_arch = "x86_64")]
    fn handle_sigill(&self, process: &mut ProcessInfo) -> Result<()> {
        if !self.emulate_insn(process)? {
            log!("Delivering SIGILL");
            process.traced_process.resume_signal(libc::SIGILL)?;
        }

        Ok(())
    }

    #[cfg(target_arch = "x86_64")]
    fn emulate_insn(&self, process: &mut ProcessInfo) -> Result<bool> {
        let mut regs = process.traced_process.get_registers()?;
        let Ok(word) = process.traced_process.read_word(regs.rip as usize) else {
            log!(
                "Not emulating instruction at {:x} -- failed to read word",
                regs.rip
            );
            return Ok(false);
        };

        if word & 0xffff == 0x310f {
            // rdtsc = 0f 31
            log!("Emulating rdtsc");
            regs.rip += 2;
            let mut tsc = unsafe { core::arch::x86_64::_rdtsc() };
            tsc += self.tsc_shift;
            regs.rdx = tsc >> 32;
            regs.rax = tsc & 0xffffffff;
            process.traced_process.set_registers(regs);
            process.traced_process.resume()?;
            Ok(true)
        } else if word & 0xffffff == 0xf9010f {
            // rdtscp = 0f 01 f9
            log!("Emulating rdtscp");
            regs.rip += 3;
            let mut tsc = unsafe { core::arch::x86_64::_rdtsc() };
            tsc += self.tsc_shift;
            regs.rdx = tsc >> 32;
            regs.rax = tsc & 0xffffffff;
            regs.rcx = 1;
            process.traced_process.set_registers(regs);
            process.traced_process.resume()?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    #[cfg(target_arch = "aarch64")]
    fn handle_sigsegv(&self, process: &mut ProcessInfo) -> Result<()> {
        log!("Delivering SIGSEGV");
        process.traced_process.resume_signal(libc::SIGSEGV)?;
        Ok(())
    }

    #[cfg(target_arch = "aarch64")]
    fn handle_sigill(&self, process: &mut ProcessInfo) -> Result<()> {
        log!("Delivering SIGILL");
        process.traced_process.resume_signal(libc::SIGILL)?;
        Ok(())
    }

    fn _handle_event(&mut self, wait_status: &system::WaitStatus) -> Result<bool> {
        match *wait_status {
            system::WaitStatus::StillAlive => {}

            system::WaitStatus::Exited(pid, _) | system::WaitStatus::Signaled(pid, _) => {
                if pid == self.main_pid {
                    log!("Main process exited");
                    return Ok(true);
                }
            }

            system::WaitStatus::Stopped(pid, signal) => {
                // Normally, we don't get signals from "unknown" processes, and SIGSTOP, which is
                // raised immediately after process start is delivered after PtraceEvent(fork). But,
                // this is not always true. One notable (first google link) example of this is
                //     https://stackoverflow.com/questions/29997244/occasionally-missing-ptrace-event-vfork-when-running-ptrace
                // where PtraceEvent(vfork) is received *after* Stopped(SIGSTOP). This case is rare
                // on my machine, and was the cause of flickering zombies and fork_bomb tests, where
                // unknown pids were marked as errors. A quick dig into linux kernel source code
                // gives us this: (only notable parts are shown)
                //
                //     // --- include/linux/ptrace.h --- //
                //     static inline void ptrace_init_task(...) {
                //         sigaddset(&child->pending.signal, SIGSTOP);
                //     }
                //
                //     // --- kernel/fork.c --- //
                //     struct task_struct *copy_process(...) {
                //         ptrace_init_task(...);
                //     }
                //
                //     /* the heart of process cloning */
                //     pid_t kernel_clone(...) {'
                //         /* Adds SIGSTOP to pending signals deep inside */
                //         p = copy_process(...);
                //         /* Wakes up task and will trigger Stopped(SIGSTOP) *later* */
                //         wake_up_new_task(p);
                //         /* Triggers PtraceEvent(fork/vfork/clone) */
                //         ptrace_event_pid(...);
                //     }
                //
                // Waking up new task before notifying about fork can sometimes lead to SIGSTOP
                // arriving before PtraceEvent.

                let mut process = match self.processes.get(&pid) {
                    Some(process) => process.borrow_mut(),
                    None => {
                        ensure!(
                            signal == libc::SIGSTOP,
                            "Unknown pid {pid} while handling Stopped on signal {signal}"
                        );

                        self.processes.insert(
                            pid,
                            RefCell::new(ProcessInfo {
                                state: ProcessState::AwaitingForkNotification,
                                traced_process: tracing::TracedProcess::new(pid)?,
                            }),
                        );

                        return Ok(false);
                    }
                };

                match signal {
                    libc::SIGSTOP => {
                        if process.state == ProcessState::JustStarted {
                            process.state = ProcessState::Alive;
                            self.on_after_fork(&mut process)?;
                            return Ok(false);
                        }
                    }
                    libc::SIGSEGV => {
                        self.handle_sigsegv(&mut process)?;
                        return Ok(false);
                    }
                    libc::SIGILL => {
                        self.handle_sigill(&mut process)?;
                        return Ok(false);
                    }
                    _ => {}
                }

                process.traced_process.resume_signal(signal)?;
            }

            system::WaitStatus::PtraceEvent(pid, _, event) => {
                if event == libc::PTRACE_EVENT_EXEC {
                    // We might not be aware of the given a pid. Consider the following situation:
                    // - Process with PID 2 starts a thread with PID 3
                    // - Process with PID 2 dies, leaving PID 3 the only running thread, but still
                    //   attached to PGID 2
                    // - Process with PID 3 executes execve, resulting in a new process with PID 2
                    //   appearing seemingly from nowhere
                    let mut process = ProcessInfo {
                        state: ProcessState::Alive,
                        traced_process: tracing::TracedProcess::new(pid)?,
                    };
                    let old_pid = Pid::from_raw(process.traced_process.get_event_msg()? as pid_t);
                    self.processes.remove(&old_pid);
                    self.on_after_execve(&mut process)?;
                    process.traced_process.resume()?;
                    self.processes.insert(pid, RefCell::new(process));
                    return Ok(false);
                }

                let Some(process) = self.processes.get(&pid) else {
                    bail!("Unknown pid {pid} while handling PtraceEvent {event}");
                };

                let mut process = process.borrow_mut();

                match event {
                    libc::PTRACE_EVENT_SECCOMP => self.on_seccomp(&mut process)?,
                    libc::PTRACE_EVENT_FORK
                    | libc::PTRACE_EVENT_VFORK
                    | libc::PTRACE_EVENT_CLONE => {
                        let child_pid =
                            Pid::from_raw(process.traced_process.get_event_msg()? as pid_t);
                        process.traced_process.resume()?;
                        drop(process);

                        match self.processes.get(&child_pid) {
                            Some(occ) => {
                                let mut old_process = occ.borrow_mut();
                                let state = &mut old_process.state;

                                // See Stopped(SIGSTOP) handling
                                ensure!(
                                    *state == ProcessState::AwaitingForkNotification,
                                    "Pid {child_pid} got PtraceEvent(fork-like) with \
                                     inappropriate state {state:?}"
                                );

                                *state = ProcessState::Alive;
                                self.on_after_fork(&mut old_process)?;
                            }
                            None => {
                                self.processes.insert(
                                    child_pid,
                                    RefCell::new(ProcessInfo {
                                        state: ProcessState::JustStarted,
                                        traced_process: tracing::TracedProcess::new(child_pid)?,
                                    }),
                                );
                            }
                        }
                    }
                    libc::PTRACE_EVENT_EXIT => {
                        process.traced_process.resume()?;
                        drop(process);
                        self.processes.remove(&pid);
                    }
                    _ => process.traced_process.resume()?,
                }
            }

            system::WaitStatus::PtraceSyscall(pid) => {
                let process = self.processes.get_mut(&pid).unwrap().get_mut();
                match &process.state {
                    ProcessState::AfterOpenMemfd(path) => {
                        std::fs::remove_file(OsStr::from_bytes(path))
                            .context("Failed to unlink /memfd:...")?;
                        process.state = ProcessState::Alive;
                        process.traced_process.resume()?;
                    }
                    _ => bail!("Unexpected process state in PtraceSyscall"),
                }
            }

            _ => {
                bail!("waitpid returned unexpected status: {wait_status:?}");
            }
        }

        Ok(false)
    }

    fn handle_event(&mut self, wait_status: &system::WaitStatus) -> Result<bool> {
        log!("Event {wait_status:?}");

        // ptrace often reports ESRCH if the process is killed before we notice that
        let res = self._handle_event(wait_status);
        if let Err(ref e) = res {
            // Not the nicest solution, certainly
            if let Some(errno::Errno::ESRCH) = e.root_cause().downcast_ref::<errno::Errno>() {
                log!(
                    warn,
                    "Got ESRCH during event handling. This indicates either a race condition when \
                     a process is killed by OOM killer or an external actor while sunwalker is \
                     working on it, or a mishandling of PIDs. If this happens more than \
                     occasionally, report this as a bug."
                );
                return Ok(false);
            }
        }
        res
    }

    fn cleanup(&mut self) -> Result<()> {
        log!("Cleaning up");

        self.box_cgroup
            .as_mut()
            .unwrap()
            .kill()
            .context("Failed to kill user cgroup")?;

        // We don't really care what happens after, but we have to waitpid() anyway
        loop {
            match system::waitpid(None, system::WaitPidFlag::__WALL) {
                Ok(wait_status) => {
                    self.handle_event(&wait_status)?;
                }
                Err(errno::Errno::ECHILD) => break,
                Err(e) => Err(e).context("Failed to waitpid")?,
            }
        }

        self.box_cgroup
            .take()
            .unwrap()
            .destroy()
            .context("Failed to destroy user cgroup")?;

        Ok(())
    }

    pub fn run(&mut self) -> Result<()> {
        // This is because no matter however small exec_wrapper is, the kernel is going to
        // preallocate stack anyway. Moreover, the stack ulimit is silently increased to at least
        // 128 KiB (ARG_MAX, to be precise), so the memory usage is going to be at least 128 KiB,
        // at least if the kernel is not patched. In practice, the minimal enforced limit is
        // slightly higher because of vdso, vvar, and other special pages.
        if let Some(memory_limit) = self.options.memory_limit {
            ensure!(
                memory_limit >= 43 * 4096,
                "Memory limit lower than 172 KiB cannot be enforced"
            );
        }

        self.runner
            .timens_controller
            .reset_system_time_for_children()
            .context("Failed to virtualize boot time")?;

        let traced_process = self.start_worker()?;

        // execve has just happened
        self.start_time = Some(Instant::now());

        let mut main_process = ProcessInfo {
            state: ProcessState::Alive,
            traced_process,
        };
        self.on_after_execve(&mut main_process)?;
        self.on_after_fork(&mut main_process)?;
        self.processes
            .insert(self.main_pid, RefCell::new(main_process));

        // If SIGPROF fires because of our actions, we capture Stopped(SIGPROF), continue the
        // process with the signal, immediately recognize that the limit has been exceeded on the
        // next iteration of the while loop and compute the verdict as CPUTimeLimitExceeded. This is
        // all regardless of how the process reacts to SIGPROF.
        //
        // If SIGPROF fires because the process wants to use it for whatever reason, we deliver the
        // signal and keep going.
        //
        // Either way, we're doing the right thing without handling SIGPROF in a special way.
        let result = try {
            let mut wait_status = system::WaitStatus::StillAlive;
            while !self.is_exceeding_limits() {
                wait_status = self.wait_for_event()?;
                self.update_metrics()?;
                if self.handle_event(&wait_status)? {
                    break;
                }
            }

            self.results.memory = self.box_cgroup.as_mut().unwrap().get_memory_peak()?;
            self.results.verdict = self.compute_verdict(wait_status)?;
        };

        self.cleanup()?;

        result
    }
}

#[crossmist::func]
fn executor_worker(
    argv: Vec<String>,
    env: Option<HashMap<String, String>>,
    stdin: File,
    stdout: File,
    stderr: File,
    mut pipe: crossmist::Sender<String>,
    exec_wrapper: File,
) -> ! {
    let e = executor_worker_impl(argv, env, stdin, stdout, stderr, exec_wrapper).into_err();

    // Ignore errors while sending error as we can't really do anything with them. stderr is now broken, so, silent death is the best solution
    let _ = pipe.send(&format!("{e:?}"));
    std::process::exit(1)
}

fn executor_worker_impl(
    argv: Vec<String>,
    env: Option<HashMap<String, String>>,
    stdin: File,
    stdout: File,
    stderr: File,
    exec_wrapper: File,
) -> Result<!> {
    // We want to disable rdtsc. Turns out, ld.so always calls rdtsc when it starts and keeps
    // using it as if it's always available. Bummer. This means we'll have to simulate rdtsc.
    timens::disable_native_instructions()
        .context("Failed to disable native timens instructions")?;

    // Only apply seccomp filter after disabling the possibility to turn rdtsc back on
    tracing::apply_seccomp_filter().context("Failed to apply seccomp filter")?;

    userns::drop_privileges().context("Failed to drop privileges")?;

    std::env::set_current_dir("/space").context("Failed to chdir to /space")?;

    unistd::dup2(stdin.as_raw_fd(), libc::STDIN_FILENO).context("dup2 for stdin failed")?;
    unistd::dup2(stdout.as_raw_fd(), libc::STDOUT_FILENO).context("dup2 for stdout failed")?;
    unistd::dup2(stderr.as_raw_fd(), libc::STDERR_FILENO).context("dup2 for stderr failed")?;

    let mut args = Vec::with_capacity(argv.len() + 1);
    args.push(CString::new("exec_wrapper")?);
    for arg in argv {
        args.push(CString::new(arg.into_bytes()).context("Argument contains null character")?);
    }

    let mut envp;
    match env {
        Some(env) => {
            envp = Vec::with_capacity(env.len());
            for (name, value) in env {
                envp.push(
                    CString::new(format!("{name}={value}").into_bytes())
                        .context("Environment variable contains null character")?,
                );
            }
        }
        None => {
            envp = Vec::new();
            for (name, value) in std::env::vars() {
                envp.push(
                    CString::new(format!("{name}={value}").into_bytes())
                        .context("Environment variable contains null character")?,
                );
            }
        }
    }

    ptrace::traceme().context("Failed to ptrace(PTRACE_TRACEME)")?;

    // We don't need to reset signals because we didn't configure them inside executor_worker()

    // If we executed the user program directly, we wouldn't be able to catch the right moment
    // to add the process to the cgroup. If we did that too early, sunwalker's memory usage
    // would be included. If we did that too late, the kernel might have loaded too big an
    // executable to memory already. Instead, we load a dummy executable that's only going to
    // use a tiny bit of memory (at most 172 KiB in practice), enforce the limits, and then let
    // the dummy execute the user program.
    match unistd::fexecve(exec_wrapper.as_raw_fd(), &args, &envp).context("execv failed")? {}
}
