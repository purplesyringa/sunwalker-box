use crate::{
    linux::{string_table, system},
    log,
};
use anyhow::{bail, ensure, Context, Result};
use nix::{
    errno::Errno,
    libc,
    libc::{c_void, off_t},
    sys::{ptrace, wait},
    unistd::Pid,
};
use std::ffi::CString;
use std::fmt::Debug;
use std::fs::File;
use std::io;
use std::io::{BufRead, BufReader, ErrorKind};
use std::os::unix::fs::FileExt;
use std::path::PathBuf;

pub struct TracedProcess {
    pid: Pid,
    external: bool,
    mem: Option<File>,
    cached_registers: Option<Result<Registers, Errno>>,
    registers_edited: bool,
}

pub struct AuxiliaryEntry {
    pub address: usize,
    pub id: usize,
    pub value: usize,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ptrace_syscall_info {
    pub op: u8,
    pub pad: [u8; 3],
    pub arch: u32,
    pub instruction_pointer: u64,
    pub stack_pointer: u64,
    pub u: ptrace_syscall_info_data,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ptrace_syscall_info_entry {
    pub nr: u64,
    pub args: [u64; 6],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ptrace_syscall_info_exit {
    pub sval: i64,
    pub is_error: u8,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ptrace_syscall_info_seccomp {
    pub nr: u64,
    pub args: [u64; 6],
    pub ret_data: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub union ptrace_syscall_info_data {
    pub entry: ptrace_syscall_info_entry,
    pub exit: ptrace_syscall_info_exit,
    pub seccomp: ptrace_syscall_info_seccomp,
}

#[repr(C)]
pub struct ptrace_rseq_configuration {
    pub rseq_abi_pointer: u64,
    pub rseq_abi_size: u32,
    pub signature: u32,
    pub flags: u32,
    pub pad: u32,
}

#[cfg(target_arch = "x86_64")]
#[derive(Clone)]
pub struct Registers(libc::user_regs_struct);

#[cfg(target_arch = "aarch64")]
#[repr(C)]
#[derive(Clone)]
pub struct Registers {
    pub regs: [u64; 31],
    pub sp: u64,
    pub pc: u64,
    pub pstate: u64,
}

#[cfg(target_arch = "x86_64")]
impl std::ops::Deref for Registers {
    type Target = libc::user_regs_struct;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
#[cfg(target_arch = "x86_64")]
impl std::ops::DerefMut for Registers {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

#[cfg(target_arch = "x86_64")]
impl Registers {
    pub fn get_stack_pointer(&self) -> usize {
        self.0.rsp as usize
    }
}

#[cfg(target_arch = "aarch64")]
impl Registers {
    pub fn get_stack_pointer(&self) -> usize {
        self.sp as usize
    }
}

#[derive(Clone, Copy)]
pub struct SyscallArgs {
    pub syscall_no: i32,
    pub args: [usize; 6],
}

impl std::fmt::Display for SyscallArgs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}({}",
            string_table::syscall_no_to_name(self.syscall_no),
            self.args[0] as isize
        )?;
        for i in 1..6 {
            write!(f, ", {}", self.args[i] as isize)?;
        }
        write!(f, ")")
    }
}

#[macro_export]
macro_rules! syscall {
    ($name:ident($($args:expr),*)) => {
        {
            // Use (|| $args)() instead of $args so that -1 is inferred as i32 as opposed to usize
            #[allow(clippy::redundant_closure_call)]
            let args = [$((|| $args)() as usize),*];
            use libc::*;
            let mut args6 = [0; 6];
            args6[..args.len()].copy_from_slice(&args);
            $crate::linux::tracing::SyscallArgs {
                syscall_no: concat_idents!(SYS_, $name) as i32,
                args: args6,
            }
        }
    }
}

#[derive(Debug, Default)]
pub struct MemoryMap {
    pub base: usize,
    pub end: usize,
    pub prot: i32,
    pub shared: bool,
    pub offset: off_t,
    pub major: u8,
    pub minor: u8,
    pub inode: u64,
    // The exact pathname is untrusted anyway, see proc(5):
    // > pathname is shown unescaped except for newline characters,
    // > which are replaced with an octal escape sequence.  As a
    // > result, it is not possible to determine whether the
    // > original pathname contained a newline character or the
    // > literal \012 character sequence.
    // >
    // > If the mapping is file-backed and the file has been
    // > deleted, the string " (deleted)" is appended to the
    // > pathname.  Note that this is ambiguous too.
    pub desc: String,
}

#[derive(Debug)]
pub struct Stat {
    // We might add more fields in the future -- this is just the subset we need for now
    pub start_code: usize,
    pub end_code: usize,
    pub start_data: usize,
    pub end_data: usize,
    pub start_stack: usize,
    pub start_brk: usize,
    pub arg_start: usize,
    pub arg_end: usize,
    pub env_start: usize,
    pub env_end: usize,
}

#[derive(Debug)]
pub struct Timer {
    pub id: i32,
    pub signal: i32,
    pub sigev_value: usize,
    pub notify: (i32, Pid),
    pub clock_id: i32,
}

impl TracedProcess {
    pub fn new(pid: Pid) -> Result<Self> {
        Self::new_external(pid, false)
    }

    pub fn new_external(pid: Pid, external: bool) -> Result<Self> {
        let mut proc = TracedProcess {
            pid,
            external,
            mem: None,
            cached_registers: None,
            registers_edited: false,
        };
        proc.reload_mm()?;
        Ok(proc)
    }

    pub fn get_pid(&self) -> Pid {
        self.pid
    }

    pub fn reload_mm(&mut self) -> Result<()> {
        self.mem = Some(self.open_mem()?);
        Ok(())
    }

    pub fn get_mem(&self) -> &File {
        self.mem.as_ref().unwrap()
    }

    fn open_mem(&self) -> Result<File> {
        let path = self.get_procfs_path("mem");
        File::options()
            .read(true)
            .write(true)
            .open(&path)
            .with_context(|| format!("Failed to open {path}"))
    }

    fn get_procfs_path(&self, name: &str) -> String {
        let prefix = if self.external { "/newroot" } else { "" };
        format!("{prefix}/proc/{}/{name}", self.pid)
    }

    pub fn detach(&self) -> Result<()> {
        ptrace::detach(self.pid, None).context("Failed to detach process")
    }

    pub fn init(&self) -> Result<()> {
        ptrace::setoptions(
            self.pid,
            ptrace::Options::PTRACE_O_TRACECLONE
                | ptrace::Options::PTRACE_O_TRACEFORK
                | ptrace::Options::PTRACE_O_TRACEVFORK
                | ptrace::Options::PTRACE_O_TRACEEXEC
                | ptrace::Options::PTRACE_O_TRACESECCOMP
                | ptrace::Options::PTRACE_O_TRACESYSGOOD,
        )
        .context("Failed to set options")
    }

    pub fn read_memory(&self, address: usize, buf: &mut [u8]) -> io::Result<()> {
        self.get_mem().read_exact_at(buf, address as u64)
    }

    pub fn read_word(&self, address: usize) -> io::Result<usize> {
        let mut word = [0u8; 8];
        self.read_memory(address, &mut word)?;
        Ok(usize::from_ne_bytes(word))
    }

    pub fn read_cstring(&self, address: usize, max_len: usize) -> io::Result<CString> {
        let mut buf = vec![0u8; max_len + 1];
        let mut offset = 0;

        while offset < max_len + 1 {
            let n_read = self.get_mem().read_at(&mut buf[offset..], address as u64)?;
            if n_read == 0 {
                return Err(io::Error::from_raw_os_error(libc::EFAULT));
            }
            if let Some(index) = buf[offset..n_read].iter().position(|&x| x == 0) {
                buf.truncate(offset + index + 1);
                unsafe {
                    return Ok(CString::from_vec_with_nul_unchecked(buf));
                }
            } else {
                offset += n_read;
            }
        }

        Err(io::Error::from_raw_os_error(libc::EINVAL))
    }

    pub fn write_memory(&self, address: usize, buf: &[u8]) -> io::Result<()> {
        self.get_mem().write_all_at(buf, address as u64)
    }

    pub fn write_word(&self, address: usize, value: usize) -> io::Result<()> {
        self.write_memory(address, &value.to_ne_bytes())
    }

    fn get_auxiliary_vector_address(&mut self) -> Result<usize> {
        let word_size = std::mem::size_of::<usize>();
        let mut address = self.get_stack_pointer()?;

        // Skip argc & argv
        let argc = self.read_word(address).context("Failed to read argc")?;
        address += word_size;
        address += (argc + 1) * word_size;

        // Skip environment
        while self
            .read_word(address)
            .context("Failed to read environment")?
            != 0
        {
            address += word_size;
        }
        address += word_size;

        // Auxiliary vector starts right after envp
        Ok(address)
    }

    pub fn get_auxiliary_entries(&mut self) -> Result<Vec<AuxiliaryEntry>> {
        let word_size = std::mem::size_of::<usize>();

        let mut address = self.get_auxiliary_vector_address()?;

        let mut entries = Vec::new();
        loop {
            let mut buf = [0u8; 16];
            self.read_memory(address, &mut buf)
                .context("Failed to read auxiliary entry")?;
            let id = usize::from_ne_bytes(buf[..8].try_into().unwrap());
            let value = usize::from_ne_bytes(buf[8..].try_into().unwrap());
            address += 2 * word_size;
            if id == libc::AT_NULL as usize {
                break;
            }
            entries.push(AuxiliaryEntry {
                address: address - 2 * word_size,
                id,
                value,
            });
        }

        Ok(entries)
    }

    pub fn disable_vdso(&mut self) -> Result<()> {
        for entry in self.get_auxiliary_entries()? {
            if entry.id == libc::AT_SYSINFO_EHDR as usize {
                self.write_word(entry.address, libc::AT_IGNORE as usize)
                    .context("Failed to write AT_IGNORE")?;
            }
        }
        Ok(())
    }

    pub fn resume(&mut self) -> Result<()> {
        self._store_registers()?;
        ptrace::cont(self.pid, None).context("Failed to ptrace-resume the child")
    }
    pub fn resume_syscall(&mut self) -> Result<()> {
        self._store_registers()?;
        ptrace::syscall(self.pid, None).context("Failed to ptrace-resume the child")
    }
    // We need to support realtime signals, which nix doesn't support -- that's why we're using i32
    // and wrapping libc here
    pub fn resume_signal(&mut self, signal: i32) -> Result<()> {
        self._store_registers()?;
        if unsafe {
            libc::ptrace(
                libc::PTRACE_CONT,
                self.pid,
                std::ptr::null_mut::<c_void>(),
                signal as *mut c_void,
            )
        } == -1
        {
            return Err(std::io::Error::last_os_error())
                .context("Failed to ptrace-resume the child");
        }
        Ok(())
    }

    pub fn get_signal_info(&self) -> Result<libc::siginfo_t> {
        ptrace::getsiginfo(self.pid).context("Failed to get signal info")
    }
    pub fn get_event_msg(&self) -> Result<libc::c_long> {
        ptrace::getevent(self.pid).context("Failed to get event")
    }
    pub fn get_syscall_info(&self) -> Result<ptrace_syscall_info> {
        let mut data = std::mem::MaybeUninit::<ptrace_syscall_info>::uninit();
        if unsafe {
            libc::ptrace(
                libc::PTRACE_GET_SYSCALL_INFO,
                self.pid.as_raw(),
                std::mem::size_of_val(&data) as *const c_void,
                data.as_mut_ptr(),
            )
        } == -1
        {
            return Err(std::io::Error::last_os_error())?;
        }
        unsafe { Ok(data.assume_init()) }
    }

    #[cfg(target_arch = "x86_64")]
    fn _get_registers(pid: Pid) -> Result<Registers, Errno> {
        ptrace::getregs(pid).map(Registers)
    }
    #[cfg(target_arch = "aarch64")]
    fn _get_registers(pid: Pid) -> Result<Registers, Errno> {
        let mut data = std::mem::MaybeUninit::<Registers>::uninit();
        let mut iovec = libc::iovec {
            iov_base: data.as_mut_ptr() as *mut c_void,
            iov_len: std::mem::size_of_val(&data),
        };
        if unsafe {
            libc::ptrace(
                libc::PTRACE_GETREGSET,
                pid.as_raw(),
                libc::NT_PRSTATUS as *mut c_void,
                &mut iovec,
            )
        } == -1
        {
            return Err(Errno::last());
        }
        if iovec.iov_len < std::mem::size_of_val(&data) {
            return Err(Errno::EINVAL);
        }
        unsafe { Ok(data.assume_init()) }
    }

    #[cfg(target_arch = "x86_64")]
    fn _set_registers(&self, regs: Registers) -> Result<()> {
        ptrace::setregs(self.pid, *regs).context("Failed to store registers of the child")
    }
    #[cfg(target_arch = "aarch64")]
    fn _set_registers(&self, regs: Registers) -> Result<()> {
        let mut iovec = libc::iovec {
            iov_base: &regs as *const _ as *mut c_void,
            iov_len: std::mem::size_of_val(&regs),
        };
        if unsafe {
            libc::ptrace(
                libc::PTRACE_SETREGSET,
                self.pid.as_raw(),
                libc::NT_PRSTATUS as *mut c_void,
                &mut iovec,
            )
        } == -1
        {
            return Err(std::io::Error::last_os_error())
                .context("Failed to store registers of the child")?;
        }
        anyhow::ensure!(
            iovec.iov_len >= std::mem::size_of_val(&regs),
            "Failed to store registers of the child: too short register set"
        );
        Ok(())
    }

    fn _load_registers(&mut self) -> io::Result<&mut Registers> {
        self.cached_registers
            .get_or_insert_with(|| Self::_get_registers(self.pid))
            .as_mut()
            .map_err(|e| (*e).into())
    }
    fn _store_registers(&mut self) -> Result<()> {
        if self.registers_edited {
            self.registers_edited = false;
            let regs = self.cached_registers.take().unwrap()?;
            self._set_registers(regs)?;
        }
        self.cached_registers = None;
        Ok(())
    }

    pub fn get_registers(&mut self) -> io::Result<Registers> {
        self._load_registers().cloned()
    }
    pub fn set_registers(&mut self, regs: Registers) {
        self.registers_edited = true;
        self.cached_registers = Some(Ok(regs));
    }

    #[cfg(target_arch = "x86_64")]
    pub fn set_active_syscall_no(&mut self, syscall_no: i32) -> io::Result<()> {
        self.registers_edited = true;
        self._load_registers()?.orig_rax = syscall_no as u64;
        Ok(())
    }
    #[cfg(target_arch = "aarch64")]
    pub fn set_active_syscall_no(&mut self, syscall_no: i32) -> io::Result<()> {
        let mut iovec = libc::iovec {
            iov_base: &syscall_no as *const _ as *mut c_void,
            iov_len: std::mem::size_of_val(&syscall_no),
        };
        if unsafe {
            libc::ptrace(
                libc::PTRACE_SETREGSET,
                self.pid.as_raw(),
                libc::NT_ARM_SYSTEM_CALL as *mut c_void,
                &mut iovec,
            )
        } == -1
        {
            return Err(std::io::Error::last_os_error());
        }
        if iovec.iov_len < std::mem::size_of_val(&syscall_no) {
            return Err(io::Error::from_raw_os_error(libc::EINVAL));
        }
        Ok(())
    }

    #[cfg(target_arch = "x86_64")]
    fn set_syscall_arg(&mut self, index: usize, arg: usize) -> io::Result<()> {
        self.registers_edited = true;
        let regs = self._load_registers()?;
        let arg = arg as u64;
        match index {
            0 => regs.rdi = arg,
            1 => regs.rsi = arg,
            2 => regs.rdx = arg,
            3 => regs.r10 = arg,
            4 => regs.r8 = arg,
            5 => regs.r9 = arg,
            _ => panic!("syscall argument index >= 6"),
        }
        Ok(())
    }
    #[cfg(target_arch = "aarch64")]
    fn set_syscall_arg(&mut self, index: usize, arg: usize) -> io::Result<()> {
        assert!(index < 6);
        self.registers_edited = true;
        let regs = self._load_registers()?;
        regs.regs[index] = arg as u64;
        Ok(())
    }

    pub fn set_syscall(&mut self, args: SyscallArgs) -> io::Result<()> {
        for (i, value) in args.args.iter().enumerate() {
            self.set_syscall_arg(i, *value)?;
        }
        self.set_active_syscall_no(args.syscall_no)
    }

    #[cfg(target_arch = "x86_64")]
    pub fn get_syscall_result(&mut self) -> io::Result<usize> {
        Ok(self._load_registers()?.rax as usize)
    }
    #[cfg(target_arch = "aarch64")]
    pub fn get_syscall_result(&mut self) -> io::Result<usize> {
        Ok(self._load_registers()?.regs[0] as usize)
    }

    #[cfg(target_arch = "x86_64")]
    pub fn set_syscall_result(&mut self, result: usize) -> io::Result<()> {
        self.registers_edited = true;
        self._load_registers()?.rax = result as u64;
        Ok(())
    }
    #[cfg(target_arch = "aarch64")]
    pub fn set_syscall_result(&mut self, result: usize) -> io::Result<()> {
        self.registers_edited = true;
        self._load_registers()?.regs[0] = result as u64;
        Ok(())
    }

    pub fn get_stack_pointer(&mut self) -> io::Result<usize> {
        Ok(self._load_registers()?.get_stack_pointer())
    }

    #[cfg(target_arch = "x86_64")]
    pub fn get_instruction_pointer(&mut self) -> io::Result<usize> {
        Ok(self._load_registers()?.rip as usize)
    }
    #[cfg(target_arch = "aarch64")]
    pub fn get_instruction_pointer(&mut self) -> io::Result<usize> {
        Ok(self._load_registers()?.pc as usize)
    }

    #[cfg(target_arch = "x86_64")]
    pub fn set_instruction_pointer(&mut self, address: usize) -> io::Result<()> {
        self.registers_edited = true;
        self._load_registers()?.rip = address as u64;
        Ok(())
    }
    #[cfg(target_arch = "aarch64")]
    pub fn set_instruction_pointer(&mut self, address: usize) -> io::Result<()> {
        self.registers_edited = true;
        self._load_registers()?.pc = address as u64;
        Ok(())
    }

    #[cfg(target_arch = "x86_64")]
    pub fn get_syscall_insn_length(&self) -> usize {
        2
    }
    #[cfg(target_arch = "aarch64")]
    pub fn get_syscall_insn_length(&self) -> usize {
        2
    }

    pub fn get_signal_mask(&self) -> Result<u64> {
        let mut mask = 0;
        if unsafe { libc::ptrace(libc::PTRACE_GETSIGMASK, self.pid.as_raw(), 8, &mut mask) } == -1 {
            return Err(std::io::Error::last_os_error())?;
        }
        Ok(mask)
    }
    pub fn set_signal_mask(&self, mask: u64) -> Result<()> {
        if unsafe { libc::ptrace(libc::PTRACE_SETSIGMASK, self.pid.as_raw(), 8, &mask) } == -1 {
            return Err(std::io::Error::last_os_error())?;
        }
        Ok(())
    }

    pub fn wait_for_ptrace_syscall(&self) -> Result<()> {
        let wait_status = wait::waitpid(self.pid, None).context("Failed to waitpid for process")?;
        if let wait::WaitStatus::PtraceSyscall(..) = wait_status {
            return Ok(());
        }
        bail!(
            "waitpid returned unexpected status at mmap: {wait_status:?}, expected PtraceSyscall"
        );
    }

    pub fn exec_syscall(&mut self, args: SyscallArgs, inside_syscall: bool) -> Result<usize> {
        // Assuming that the instruction pointer points to a syscall instruction, execute one
        // syscall. set_syscall_no modifies orig_rax, which only makes sense after the syscall has
        // been entered.
        if !inside_syscall {
            self.set_active_syscall_no(-1)?;
            self.resume_syscall()?;
            self.wait_for_ptrace_syscall()?;
        }
        self.set_syscall(args.clone())?;
        self.resume_syscall()?;
        self.wait_for_ptrace_syscall()?;
        let result = self.get_syscall_result()?;
        if (-4095..0).contains(&(result as isize)) {
            let errno = -(result as i32);
            log!(
                "<pid {}> {args} = -{}",
                self.pid,
                string_table::errno_to_name(errno)
            );
            Err(io::Error::from_raw_os_error(errno))?
        } else {
            log!("<pid {}> {args} = {result}", self.pid);
            Ok(result)
        }
    }

    pub fn get_memory_maps(&self) -> Result<Vec<MemoryMap>> {
        let mut maps: Vec<MemoryMap> = Vec::new();

        let path = self.get_procfs_path("maps");
        let file = File::open(&path).with_context(|| format!("Failed to open {path}"))?;
        for line in BufReader::new(file).split(b'\n') {
            let mut line = &line.with_context(|| format!("Failed to read {path}"))?[..];

            let mut split_by = |split_c: u8| -> Result<&str> {
                let pos = line
                    .iter()
                    .position(|&c| c == split_c)
                    .context("Invalid maps format")?;
                let s = &line[..pos];
                line = &line[pos + 1..];
                std::str::from_utf8(s).context("Invalid maps format")
            };

            let base = usize::from_str_radix(split_by(b'-')?, 16).context("Invalid maps format")?;
            let end = usize::from_str_radix(split_by(b' ')?, 16).context("Invalid maps format")?;

            let prot = split_by(b' ')?.as_bytes();
            ensure!(prot.len() == 4, "Invalid maps format");
            let shared = prot[3] == b's';
            let mut prot = if prot[0] == b'r' { libc::PROT_READ } else { 0 }
                | if prot[1] == b'w' { libc::PROT_WRITE } else { 0 }
                | if prot[2] == b'x' { libc::PROT_EXEC } else { 0 };
            if prot == 0 {
                prot = libc::PROT_NONE;
            }

            let offset =
                off_t::from_str_radix(split_by(b' ')?, 16).context("Invalid maps format")?;
            let major = u8::from_str_radix(split_by(b':')?, 16).context("Invalid maps format")?;
            let minor = u8::from_str_radix(split_by(b' ')?, 16).context("Invalid maps format")?;
            let inode = split_by(b' ')?.parse().context("Invalid maps format")?;

            let mut desc = String::new();
            if let Some(pos) = line.iter().position(|&c| c != b' ') {
                // Only special mappings may have such pathnames
                if line[pos] == b'[' && *line.last().unwrap() == b']' {
                    desc =
                        String::from_utf8(line[pos..].to_vec()).context("Invalid maps format")?;
                }
            }

            maps.push(MemoryMap {
                base,
                end,
                prot,
                shared,
                offset,
                major,
                minor,
                inode,
                desc,
            });
        }

        Ok(maps)
    }

    pub fn get_memory_mapped_file_path(&self, map: &MemoryMap) -> Result<Option<PathBuf>> {
        let path = self.get_procfs_path(&format!("map_files/{:x}-{:x}", map.base, map.end));
        match std::fs::read_link(&path) {
            Ok(path) => Ok(Some(path)),
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e).context(format!("Failed to readlink {path}")),
        }
    }

    pub fn get_rseq_configuration(&self) -> Result<ptrace_rseq_configuration> {
        let mut data = std::mem::MaybeUninit::<ptrace_rseq_configuration>::uninit();
        if unsafe {
            libc::ptrace(
                libc::PTRACE_GET_RSEQ_CONFIGURATION,
                self.pid.as_raw(),
                std::mem::size_of_val(&data) as *const c_void,
                data.as_mut_ptr(),
            )
        } == -1
        {
            return Err(std::io::Error::last_os_error())?;
        }
        unsafe { Ok(data.assume_init()) }
    }

    pub fn get_stat(&self) -> Result<Stat> {
        let path = self.get_procfs_path("stat");
        let buf = std::fs::read(&path).with_context(|| format!("Failed to open {path}"))?;

        let pos = buf
            .iter()
            .rposition(|&c| c == b')')
            .context("Invalid stat format")?;
        let mut fields = std::str::from_utf8(&buf[pos..])
            .context("Invalid stat format")?
            .split(' ');

        for _ in 0..24 {
            fields.next().context("Invalid stat format")?;
        }
        let start_code = fields.next().context("Invalid stat format")?.parse()?;
        let end_code = fields.next().context("Invalid stat format")?.parse()?;
        let start_stack = fields.next().context("Invalid stat format")?.parse()?;
        for _ in 0..16 {
            fields.next().context("Invalid stat format")?;
        }
        let start_data = fields.next().context("Invalid stat format")?.parse()?;
        let end_data = fields.next().context("Invalid stat format")?.parse()?;
        let start_brk = fields.next().context("Invalid stat format")?.parse()?;
        let arg_start = fields.next().context("Invalid stat format")?.parse()?;
        let arg_end = fields.next().context("Invalid stat format")?.parse()?;
        let env_start = fields.next().context("Invalid stat format")?.parse()?;
        let env_end = fields.next().context("Invalid stat format")?.parse()?;

        Ok(Stat {
            start_code,
            end_code,
            start_data,
            end_data,
            start_stack,
            start_brk,
            arg_start,
            arg_end,
            env_start,
            env_end,
        })
    }

    pub fn wait(&self) -> Result<system::WaitStatus> {
        system::waitpid(Some(self.get_pid()), system::WaitPidFlag::empty())
            .context("Failed to wait for traced process")
    }
}

impl Debug for TracedProcess {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(fmt, "traced process {}", self.pid)
    }
}

pub fn apply_seccomp_filter(restricted: bool) -> Result<()> {
    let filter = if restricted {
        &include_bytes!("../../target/filter_restricted.seccomp.out")[..]
    } else {
        &include_bytes!("../../target/filter.seccomp.out")[..]
    };
    let prog = libc::sock_fprog {
        len: (filter.len() / 8) as u16,
        filter: filter.as_ptr() as *mut libc::sock_filter,
    };

    if unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            libc::SECCOMP_SET_MODE_FILTER,
            // We don't want to force SSBD upon users if it harms performance and their threat model
            // allows for it
            libc::SECCOMP_FILTER_FLAG_LOG | libc::SECCOMP_FILTER_FLAG_SPEC_ALLOW,
            &prog as *const libc::sock_fprog,
        )
    } == -1
    {
        Err(std::io::Error::last_os_error())?;
    }
    Ok(())
}
