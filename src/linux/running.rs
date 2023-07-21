use crate::linux::{cgroups, ipc, rootfs, timens, tracing, userns};
use anyhow::{bail, Context, Result};
use multiprocessing::Object;
use nix::{
    errno, libc,
    libc::pid_t,
    sys::{epoll, memfd, ptrace, signal, signalfd, wait},
    unistd,
    unistd::Pid,
};
use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::fs::File;
use std::io::Write;
use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd};
use std::time::{Duration, Instant};

pub struct Runner {
    proc_cgroup: cgroups::ProcCgroup,
    timens_controller: timens::TimeNsController,
    sigfd: signalfd::SignalFd,
    epollfd: OwnedFd,
    exec_wrapper: File,
}

#[derive(Object)]
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

#[derive(PartialEq, Eq)]
enum ProcessState {
    JustStarted,
    Alive,
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
    has_peak: bool,
    main_pid: Pid,
    start_time: Option<Instant>,
    processes: HashMap<Pid, ProcessInfo>,
    tsc_shift: u64,
    sem_next_id: isize,
    msg_next_id: isize,
    shm_next_id: isize,
}

impl Runner {
    pub fn new(proc_cgroup: cgroups::ProcCgroup) -> Result<Self> {
        // Mount procfs and enter the sandboxed root
        rootfs::configure_rootfs().context("Failed to configure rootfs")?;
        let timens_controller = timens::TimeNsController::new().context("Failed to adjust time")?;
        userns::enter_user_namespace().context("Failed to unshare user namespace")?;
        rootfs::enter_rootfs().context("Failed to enter rootfs")?;

        // Unshare IPC namespace now, so that it is owned by the new userns and can be configured
        ipc::unshare_ipc_namespace().context("Failed to unshare IPC namespace")?;

        // Create signalfd to watch child's state change
        let mut sigset = signal::SigSet::empty();
        sigset.add(signal::Signal::SIGCHLD);
        sigset.thread_block().context("Failed to block SIGCHLD")?;
        let sigfd = signalfd::SignalFd::with_flags(
            &sigset,
            signalfd::SfdFlags::SFD_NONBLOCK | signalfd::SfdFlags::SFD_CLOEXEC,
        )
        .context("Failed to create signalfd")?;

        let epollfd = epoll::epoll_create1(epoll::EpollCreateFlags::EPOLL_CLOEXEC)
            .context("Failed to create epollfd")?;
        let epollfd = unsafe { OwnedFd::from_raw_fd(epollfd) };
        epoll::epoll_ctl(
            epollfd.as_raw_fd(),
            epoll::EpollOp::EpollCtlAdd,
            sigfd.as_raw_fd(),
            &mut epoll::EpollEvent::new(epoll::EpollFlags::EPOLLIN, 0),
        )
        .context("Failed to configure epoll")?;

        let mut exec_wrapper = unsafe {
            File::from_raw_fd(
                memfd::memfd_create(
                    CStr::from_bytes_with_nul_unchecked(b"exec_wrapper\0"),
                    memfd::MemFdCreateFlag::MFD_CLOEXEC,
                )
                .context("Failed to create memfd for exec_wrapper")?,
            )
        };
        exec_wrapper
            .write_all(include_bytes!("../../target/exec_wrapper"))
            .context("Failed to fill exec_wrapper memfd")?;

        Ok(Runner {
            proc_cgroup,
            timens_controller,
            sigfd,
            epollfd,
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
            has_peak: false,
            main_pid: Pid::from_raw(0),
            start_time: None,
            processes: HashMap::new(),
            tsc_shift: rand::random::<u64>(),
            sem_next_id: 0,
            msg_next_id: 0,
            shm_next_id: 0,
        };
        single_run.run()?;
        Ok(single_run.results)
    }
}

impl SingleRun<'_> {
    fn open_standard_streams(&self) -> Result<[File; 3]> {
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
        let (theirs, mut ours) = multiprocessing::channel().context("Failed to create a pipe")?;
        let user_process = executor_worker
            .spawn(
                self.options.argv.clone(),
                self.options.env.clone(),
                stdin,
                stdout,
                stderr,
                theirs,
                self.options.cpu_time_limit,
                self.runner
                    .exec_wrapper
                    .try_clone()
                    .context("Failed to clone exec_wrapper")?,
            )
            .context("Failed to spawn the child")?;
        self.main_pid = Pid::from_raw(user_process.id());

        // The child will either exit or trigger SIGTRAP on execve() to exec_wrapper due to ptrace
        let wait_status =
            wait::waitpid(self.main_pid, None).context("Failed to waitpid for process")?;

        match wait_status {
            wait::WaitStatus::Exited(_, _) => {
                bail!(
                    "{}",
                    ours.recv()
                        .context("Failed to read an error from the child")?
                        .context("The child terminated but did not report any error")?
                );
            }
            wait::WaitStatus::Stopped(_, signal::Signal::SIGTRAP) => {}
            _ => {
                bail!("waitpid returned unexpected status: {wait_status:?}");
            }
        };

        // Apply cgroup limits
        self.create_box_cgroup()?;
        self.box_cgroup
            .as_mut()
            .unwrap()
            .add_process(self.main_pid.as_raw())
            .context("Failed to move the child to user cgroup")?;

        // execve() the real program
        let mut traced_process = tracing::TracedProcess::new(self.main_pid)?;
        traced_process.resume()?;

        // The child will either exit or trigger SIGTRAP on execve() to the real program
        let wait_status =
            wait::waitpid(self.main_pid, None).context("Failed to waitpid for process")?;

        match wait_status {
            wait::WaitStatus::Exited(_, exit_code) => {
                let errno = exit_code;
                bail!(
                    "Failed to start program with error {}",
                    std::io::Error::from_raw_os_error(errno)
                );
            }
            wait::WaitStatus::Stopped(_, signal::Signal::SIGTRAP) => {
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

        // Old kernels don't reveal memory.peak, so the only way to get memory usage stats is to use
        // polling
        if !self.has_peak {
            timeout = Duration::from_millis(50);
        }

        if timeout == Duration::MAX {
            -1
        } else {
            // Old kernels don't support very large timeouts
            timeout
                .as_millis()
                .try_into()
                .unwrap_or(i32::MAX)
                .min(1000000)
        }
    }

    fn is_exceeding_limits(&self) -> bool {
        self.options
            .cpu_time_limit
            .is_some_and(|limit| self.results.cpu_time > limit)
            || self
                .options
                .real_time_limit
                .is_some_and(|limit| self.results.real_time > limit)
            || self
                .options
                .idleness_time_limit
                .is_some_and(|limit| self.results.idleness_time > limit)
            || self
                .options
                .memory_limit
                .is_some_and(|limit| self.results.memory > limit)
    }

    fn compute_verdict(&self, wait_status: wait::WaitStatus) -> Result<Verdict> {
        if self
            .options
            .cpu_time_limit
            .is_some_and(|limit| self.results.cpu_time > limit)
        {
            return Ok(Verdict::CPUTimeLimitExceeded);
        }
        if self
            .options
            .real_time_limit
            .is_some_and(|limit| self.results.real_time > limit)
        {
            return Ok(Verdict::RealTimeLimitExceeded);
        }
        if self
            .options
            .idleness_time_limit
            .is_some_and(|limit| self.results.idleness_time > limit)
        {
            return Ok(Verdict::IdlenessTimeLimitExceeded);
        }
        if self.box_cgroup.as_ref().unwrap().was_oom_killed()?
            || self
                .options
                .memory_limit
                .is_some_and(|limit| self.results.memory > limit)
        {
            return Ok(Verdict::MemoryLimitExceeded);
        }
        match wait_status {
            wait::WaitStatus::Exited(_, exit_code) => Ok(Verdict::ExitCode(exit_code)),
            wait::WaitStatus::Signaled(_, signal, _) => {
                if signal == signal::Signal::SIGPROF {
                    Ok(Verdict::CPUTimeLimitExceeded)
                } else {
                    Ok(Verdict::Signaled(signal as i32))
                }
            }
            _ => {
                bail!("waitpid returned unexpected status: {wait_status:?}");
            }
        }
    }

    fn wait_for_event(&mut self) -> Result<wait::WaitStatus> {
        let wait_status = wait::waitpid(
            None,
            Some(wait::WaitPidFlag::__WALL | wait::WaitPidFlag::WNOHANG),
        )
        .context("Failed to waitpid for process")?;
        if wait_status != wait::WaitStatus::StillAlive {
            return Ok(wait_status);
        }

        let timeout_ms = self.compute_wait_timeout_ms();
        let mut events = [epoll::EpollEvent::empty()];
        let n_events = epoll::epoll_wait(
            self.runner.epollfd.as_raw_fd(),
            &mut events,
            timeout_ms as isize,
        )
        .context("epoll_wait failed")?;

        match n_events {
            0 => Ok(wait::WaitStatus::StillAlive),
            1 => {
                while self
                    .runner
                    .sigfd
                    .read_signal()
                    .context("Failed to read signal")?
                    .is_some()
                {}

                Ok(wait::waitpid(
                    None,
                    Some(wait::WaitPidFlag::__WALL | wait::WaitPidFlag::WNOHANG),
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
        if !self.has_peak {
            self.results.memory = self
                .results
                .memory
                .max(self.box_cgroup.as_mut().unwrap().get_memory_total()?);
        }
        Ok(())
    }

    fn on_after_fork(process: &ProcessInfo) -> Result<()> {
        process.traced_process.init()?;
        Ok(())
    }

    fn on_after_execve(process: &ProcessInfo) -> Result<()> {
        // Required to make clock_gettime work
        process.traced_process.disable_vdso()?;
        Ok(())
    }

    fn on_seccomp(&mut self, pid: Pid) -> Result<()> {
        let process = self
            .processes
            .get_mut(&pid)
            .with_context(|| format!("Unknown pid {pid}"))?;

        let syscall_info = process
            .traced_process
            .get_syscall_info()
            .context("Failed to get syscall info")?;
        let syscall_info = unsafe { syscall_info.u.seccomp };

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
                if ipc::get_next_id("sem")? == -1 {
                    ipc::set_next_id("sem", self.sem_next_id)?;
                    self.sem_next_id += 1;
                }
                return Self::emulate_syscall_result_errno(process, unsafe {
                    libc::semget(
                        syscall_info.args[0] as i32,
                        syscall_info.args[1] as i32,
                        syscall_info.args[2] as i32,
                    )
                } as i64);
            }
            libc::SYS_msgget => {
                if ipc::get_next_id("msg")? == -1 {
                    ipc::set_next_id("msg", self.msg_next_id)?;
                    self.msg_next_id += 1;
                }
                return Self::emulate_syscall_result_errno(process, unsafe {
                    libc::msgget(syscall_info.args[0] as i32, syscall_info.args[1] as i32)
                } as i64);
            }
            libc::SYS_shmget => {
                if ipc::get_next_id("shm")? == -1 {
                    ipc::set_next_id("shm", self.shm_next_id)?;
                    self.shm_next_id += 1;
                }
                return Self::emulate_syscall_result_errno(process, unsafe {
                    libc::shmget(
                        syscall_info.args[0] as i32,
                        syscall_info.args[1] as usize,
                        syscall_info.args[2] as i32,
                    )
                } as i64);
            }
            libc::SYS_memfd_create => {
                return Self::emulate_syscall_redirect(process, |process, regs| {
                    let mut name = process
                        .traced_process
                        .read_cstring(syscall_info.args[0] as usize, 249)?
                        .into_bytes_with_nul();

                    let mut open_flags = libc::O_RDWR | libc::O_CREAT;
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

                    // We don't care about .. in this context because open(2) is executed in the
                    // context of the unprivileged process, and no sane person is going to use ..
                    // in the name for benign reasons.
                    let mut file_name =
                        format!("/dev/shm/memfd:{:08x}:", rand::random::<u32>()).into_bytes();
                    file_name.append(&mut name);

                    let file_name_addr =
                        (tracing::get_stack_pointer(&regs) - 128) as usize - file_name.len();

                    process
                        .traced_process
                        .write_memory(file_name_addr, &file_name)?;

                    Ok((libc::SYS_open, [file_name_addr, open_flags as usize, 0o700]))
                });
            }
            _ => {}
        }

        process.traced_process.resume()?;
        Ok(())
    }

    fn emulate_syscall_result_errno(process: &mut ProcessInfo, mut result: i64) -> Result<()> {
        if result == -1 {
            result = -errno::errno() as i64;
        }
        Self::emulate_syscall_result(process, result)
    }

    fn emulate_syscall_result(process: &mut ProcessInfo, result: i64) -> Result<()> {
        let mut regs = process.traced_process.get_registers()?;
        regs.rax = result as u64;
        regs.orig_rax = u64::MAX; // skip syscall
        process.traced_process.set_registers(regs)?;
        process.state = ProcessState::Alive;
        process.traced_process.resume()?;
        Ok(())
    }

    fn emulate_syscall_redirect<const N: usize>(
        process: &mut ProcessInfo,
        redirect: impl FnOnce(
            &mut ProcessInfo,
            &libc::user_regs_struct,
        ) -> std::io::Result<(i64, [usize; N])>,
    ) -> Result<()> {
        let mut regs = process.traced_process.get_registers()?;
        match redirect(process, &regs) {
            Ok((syscall_no, args)) => {
                regs.orig_rax = syscall_no as u64;
                if N >= 1 {
                    regs.rdi = args[0] as u64;
                }
                if N >= 2 {
                    regs.rsi = args[1] as u64;
                }
                if N >= 3 {
                    regs.rdx = args[2] as u64;
                }
                if N >= 4 {
                    regs.r10 = args[3] as u64;
                }
                if N >= 5 {
                    regs.r8 = args[4] as u64;
                }
                if N >= 6 {
                    regs.r9 = args[5] as u64;
                }
            }
            Err(err) => {
                regs.orig_rax = u64::MAX; // skip syscall
                regs.rax = -err.raw_os_error().unwrap_or(libc::EINVAL) as u64;
            }
        }
        process.traced_process.set_registers(regs)?;
        process.state = ProcessState::Alive;
        process.traced_process.resume()?;
        Ok(())
    }

    #[cfg(target_arch = "x86_64")]
    fn handle_sigsegv(&self, process: &ProcessInfo) -> Result<()> {
        let info = process.traced_process.get_signal_info()?;
        if info.si_signo != signal::Signal::SIGSEGV as i32 {
            // Excuse me?
            bail!(
                "This shouldn't happen: signal number mismatch between waitpid and \
                 PTRACE_GETSIGINFO"
            );
        }

        const SI_KERNEL: i32 = 128;
        if info.si_code == SI_KERNEL {
            let fault_address = unsafe { info.si_addr() as usize };
            if fault_address == 0 {
                // rdtsc fails with #GP(0)
                let mut regs = process.traced_process.get_registers()?;
                if let Ok(word) = process.traced_process.read_word(regs.rip as usize) {
                    if word & 0xffff == 0x310f {
                        // rdtsc = 0f 31
                        regs.rip += 2;
                        let mut tsc = unsafe { core::arch::x86_64::_rdtsc() };
                        tsc += self.tsc_shift;
                        regs.rdx = tsc >> 32;
                        regs.rax = tsc & 0xffffffff;
                        process.traced_process.set_registers(regs)?;
                        process.traced_process.resume()?;
                        return Ok(());
                    } else if word & 0xffffff == 0xf9010f {
                        // rdtscp = 0f 01 f9
                        regs.rip += 3;
                        let mut aux = 0;
                        let mut tsc = unsafe { core::arch::x86_64::__rdtscp(&mut aux) };
                        tsc += self.tsc_shift;
                        regs.rdx = tsc >> 32;
                        regs.rax = tsc & 0xffffffff;
                        regs.rcx = aux as u64;
                        process.traced_process.set_registers(regs)?;
                        process.traced_process.resume()?;
                        return Ok(());
                    }
                }
            }
        }

        process
            .traced_process
            .resume_signal(signal::Signal::SIGSEGV)?;
        Ok(())
    }

    #[cfg(target_arch = "aarch64")]
    fn handle_sigsegv(&self, process: &ProcessInfo) -> Result<()> {
        process
            .traced_process
            .resume_signal(signal::Signal::SIGSEGV)?;
        Ok(())
    }

    fn _handle_event(&mut self, wait_status: wait::WaitStatus) -> Result<bool> {
        match wait_status {
            wait::WaitStatus::StillAlive => {}

            wait::WaitStatus::Exited(pid, _) | wait::WaitStatus::Signaled(pid, _, _) => {
                if pid == self.main_pid {
                    return Ok(true);
                }
            }

            wait::WaitStatus::Stopped(pid, signal) => {
                let process = self
                    .processes
                    .get(&pid)
                    .with_context(|| format!("Unknown pid {pid}"))?;

                match signal {
                    signal::Signal::SIGSTOP => {
                        if process.state == ProcessState::JustStarted {
                            let process = self.processes.get_mut(&pid).unwrap();
                            process.state = ProcessState::Alive;
                            Self::on_after_fork(process)?;
                            process.traced_process.resume()?;
                            return Ok(false);
                        }
                    }
                    signal::Signal::SIGSEGV => {
                        self.handle_sigsegv(process)?;
                        return Ok(false);
                    }
                    _ => {}
                }

                process.traced_process.resume_signal(signal)?;
            }

            wait::WaitStatus::PtraceEvent(pid, _, event) => {
                match event {
                    libc::PTRACE_EVENT_EXEC => {
                        let process = ProcessInfo {
                            state: ProcessState::Alive,
                            traced_process: tracing::TracedProcess::new(pid)?,
                        };
                        let old_pid =
                            Pid::from_raw(process.traced_process.get_event_msg()? as pid_t);
                        self.processes.remove(&old_pid);
                        Self::on_after_execve(&process)?;
                        process.traced_process.resume()?;
                        self.processes.insert(pid, process);
                        return Ok(false);
                    }
                    libc::PTRACE_EVENT_SECCOMP => {
                        self.on_seccomp(pid)?;
                        return Ok(false);
                    }
                    _ => {}
                }

                let process = self
                    .processes
                    .get(&pid)
                    .with_context(|| format!("Unknown pid {pid}"))?;

                match event {
                    libc::PTRACE_EVENT_FORK
                    | libc::PTRACE_EVENT_VFORK
                    | libc::PTRACE_EVENT_CLONE => {
                        let child_pid =
                            Pid::from_raw(process.traced_process.get_event_msg()? as pid_t);
                        process.traced_process.resume()?;
                        self.processes.insert(
                            child_pid,
                            ProcessInfo {
                                state: ProcessState::JustStarted,
                                traced_process: tracing::TracedProcess::new(child_pid)?,
                            },
                        );
                    }
                    libc::PTRACE_EVENT_EXIT => {
                        process.traced_process.resume()?;
                        self.processes.remove(&pid);
                    }
                    _ => process.traced_process.resume()?,
                }
            }

            wait::WaitStatus::PtraceSyscall(pid) => {
                let process = self.processes.get_mut(&pid).unwrap();
                process.state = ProcessState::Alive;
                process.traced_process.resume()?;
            }

            _ => {
                bail!("waitpid returned unexpected status: {wait_status:?}");
            }
        }

        Ok(false)
    }

    fn handle_event(&mut self, wait_status: wait::WaitStatus) -> Result<bool> {
        // ptrace often reports ESRCH if the process is killed before we notice that
        let res = self._handle_event(wait_status);
        if let Err(ref e) = res {
            // Not the nicest solution, certainly
            if let Some(errno::Errno::ESRCH) = e.root_cause().downcast_ref::<errno::Errno>() {
                return Ok(false);
            }
        }
        res
    }

    fn cleanup(&mut self) -> Result<()> {
        self.box_cgroup
            .as_mut()
            .unwrap()
            .kill()
            .context("Failed to kill user cgroup")?;

        // We don't really care what happens after, but we have to waitpid() anyway
        loop {
            match wait::waitpid(None, Some(wait::WaitPidFlag::__WALL)) {
                Ok(wait_status) => {
                    self.handle_event(wait_status)?;
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
            if memory_limit < 43 * 4096 {
                bail!("Memory limit lower than 172 KiB cannot be enforced");
            }
        }

        self.runner
            .timens_controller
            .reset_system_time_for_children()
            .context("Failed to virtualize boot time")?;

        let traced_process = self.start_worker()?;

        self.has_peak = self
            .box_cgroup
            .as_mut()
            .unwrap()
            .get_memory_peak()?
            .is_some();

        // execve has just happened
        self.start_time = Some(Instant::now());

        self.processes.insert(
            self.main_pid,
            ProcessInfo {
                state: ProcessState::Alive,
                traced_process,
            },
        );
        let main_process = self.processes.get(&self.main_pid).unwrap();

        Self::on_after_fork(main_process)?;
        Self::on_after_execve(main_process)?;
        main_process.traced_process.resume()?;

        let mut wait_status = wait::WaitStatus::StillAlive;
        while !self.is_exceeding_limits() {
            wait_status = self.wait_for_event()?;
            if self.handle_event(wait_status)? {
                break;
            }
            self.update_metrics()?;
        }

        if self.has_peak {
            self.results.memory = self.results.memory.max(
                self.box_cgroup
                    .as_mut()
                    .unwrap()
                    .get_memory_peak()?
                    .context("memory.peak is unexpectedly unavailable")?,
            );
        }

        self.results.verdict = self.compute_verdict(wait_status)?;

        self.cleanup()?;

        Ok(())
    }
}

#[multiprocessing::func]
fn executor_worker(
    argv: Vec<String>,
    env: Option<HashMap<String, String>>,
    stdin: File,
    stdout: File,
    stderr: File,
    mut pipe: multiprocessing::Sender<String>,
    cpu_time_limit: Option<Duration>,
    exec_wrapper: File,
) {
    let result: Result<()> = try {
        tracing::apply_seccomp_filter().context("Failed to apply seccomp filter")?;

        userns::drop_privileges().context("Failed to drop privileges")?;

        // We want to disable rdtsc. Turns out, ld.so always calls rdtsc when it starts and keeps
        // using it as if it's always available. Bummer. This means we'll have to simulate rdtsc.
        timens::disable_rdtsc().context("Failed to disable rdtsc")?;

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

        if let Some(cpu_time_limit) = cpu_time_limit {
            // An additional optimization for finer handling of cpu time limit. An ITIMER_PROF timer
            // can emit a signal when the given limit is exceeded and is not reset upon execve. This
            // only applies to a single process, not a cgroup, and can be overwritten by the user
            // program, but this feature is not mission-critical. It merely saves us a few precious
            // milliseconds due to the (somewhat artificially deliberate) inefficiency of polling.
            let timer = libc::itimerval {
                it_interval: libc::timeval {
                    tv_sec: 0,
                    tv_usec: 0,
                },
                it_value: libc::timeval {
                    tv_sec: cpu_time_limit.as_secs() as i64,
                    tv_usec: cpu_time_limit.subsec_micros() as i64,
                },
            };
            if unsafe {
                libc::syscall(
                    libc::SYS_setitimer,
                    libc::ITIMER_PROF,
                    &timer as *const libc::itimerval,
                    std::ptr::null_mut::<libc::itimerval>(),
                )
            } == -1
            {
                Err(std::io::Error::last_os_error()).context("Failed to set interval timer")?;
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
        unistd::fexecve(exec_wrapper.as_raw_fd(), &args, &envp).context("execv failed")?;
    };

    if let Err(e) = result {
        pipe.send(&format!("{e:?}"))
            .expect("Failed to report error to parent");
    }
}
