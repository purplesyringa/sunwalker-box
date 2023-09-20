use crate::{linux::string_table, log};
use anyhow::{bail, ensure, Context, Result};
use crossmist::{Deserializer, NonTrivialObject, Object, Serializer};
use nix::{
    errno::Errno,
    libc,
    libc::{c_uint, c_void, off_t},
    sys::{ptrace, signal, wait},
    unistd::Pid,
};
use std::ffi::CString;
use std::fmt::Write;
use std::fs::File;
use std::io;
use std::io::{BufRead, BufReader};
use std::ops::{Deref, DerefMut};
use std::os::unix::fs::FileExt;

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

const AT_SYSINFO_EHDR: u64 = 33; // x86-64
const SECCOMP_SET_MODE_FILTER: c_uint = 1;
const PTRACE_GET_SYSCALL_INFO: i32 = 0x420e;

#[cfg(target_arch = "aarch64")]
const NT_PRSTATUS: i32 = 1;

#[cfg(target_arch = "aarch64")]
const NT_ARM_SYSTEM_CALL: i32 = 0x404;

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

#[cfg(target_arch = "aarch64")]
#[repr(C)]
#[derive(Clone, Object)]
pub struct user_pt_regs {
    pub regs: [u64; 31],
    pub sp: u64,
    pub pc: u64,
    pub pstate: u64,
}

#[cfg(target_arch = "x86_64")]
#[derive(Clone)]
pub struct Registers(libc::user_regs_struct);
#[cfg(target_arch = "aarch64")]
pub type Registers = user_pt_regs;

#[cfg(target_arch = "x86_64")]
impl Deref for Registers {
    type Target = libc::user_regs_struct;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
#[cfg(target_arch = "x86_64")]
impl DerefMut for Registers {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
#[cfg(target_arch = "x86_64")]
impl NonTrivialObject for Registers {
    fn serialize_self_non_trivial(&self, s: &mut Serializer) {
        unsafe {
            s.serialize(&std::mem::transmute::<
                Self,
                [u8; std::mem::size_of::<Self>()],
            >(self.clone()));
        }
    }
    unsafe fn deserialize_self_non_trivial(d: &mut Deserializer) -> Self {
        unsafe { std::mem::transmute(d.deserialize::<[u8; std::mem::size_of::<Self>()]>()) }
    }
    unsafe fn deserialize_on_heap_non_trivial<'a>(
        &self,
        d: &mut Deserializer,
    ) -> Box<dyn Object + 'a>
    where
        Self: 'a,
    {
        Box::new(Self::deserialize_self(d))
    }
}

pub trait SyscallArgs: Clone {
    const N: usize;
    fn to_usize_slice(&self) -> [usize; Self::N];
    fn debug(&self) -> String
    where
        [(); Self::N]:,
    {
        let mut s = String::new();
        let slice = self.to_usize_slice();
        write!(s, "{}(", string_table::syscall_no_to_name(slice[0] as i32)).unwrap();
        for (i, value) in slice.iter().skip(1).enumerate() {
            if i > 0 {
                write!(s, ", ").unwrap();
            }
            write!(s, "{}", *value as isize).unwrap();
        }
        write!(s, ")").unwrap();
        s
    }
}

pub trait AsUSize: Copy {
    fn as_usize(self) -> usize;
}

macro_rules! impl_for {
    () => {};
    ($head:tt $($tail:tt)*) => {
        impl AsUSize for $head {
            fn as_usize(self) -> usize {
                self as usize
            }
        }
        impl_for!($($tail)*);
    };
}

impl_for!(u8 u16 u32 u64 usize i8 i16 i32 i64 isize char bool);

impl<T> AsUSize for *const T {
    fn as_usize(self) -> usize {
        self as usize
    }
}

impl<T> AsUSize for *mut T {
    fn as_usize(self) -> usize {
        self as usize
    }
}

impl<T1: AsUSize> SyscallArgs for (T1,) {
    const N: usize = 1;
    fn to_usize_slice(&self) -> [usize; Self::N] {
        [self.0.as_usize()]
    }
}
impl<T1: AsUSize, T2: AsUSize> SyscallArgs for (T1, T2) {
    const N: usize = 2;
    fn to_usize_slice(&self) -> [usize; Self::N] {
        [self.0.as_usize(), self.1.as_usize()]
    }
}
impl<T1: AsUSize, T2: AsUSize, T3: AsUSize> SyscallArgs for (T1, T2, T3) {
    const N: usize = 3;
    fn to_usize_slice(&self) -> [usize; Self::N] {
        [self.0.as_usize(), self.1.as_usize(), self.2.as_usize()]
    }
}
impl<T1: AsUSize, T2: AsUSize, T3: AsUSize, T4: AsUSize> SyscallArgs for (T1, T2, T3, T4) {
    const N: usize = 4;
    fn to_usize_slice(&self) -> [usize; Self::N] {
        [
            self.0.as_usize(),
            self.1.as_usize(),
            self.2.as_usize(),
            self.3.as_usize(),
        ]
    }
}
impl<T1: AsUSize, T2: AsUSize, T3: AsUSize, T4: AsUSize, T5: AsUSize> SyscallArgs
    for (T1, T2, T3, T4, T5)
{
    const N: usize = 5;
    fn to_usize_slice(&self) -> [usize; Self::N] {
        [
            self.0.as_usize(),
            self.1.as_usize(),
            self.2.as_usize(),
            self.3.as_usize(),
            self.4.as_usize(),
        ]
    }
}
impl<T1: AsUSize, T2: AsUSize, T3: AsUSize, T4: AsUSize, T5: AsUSize, T6: AsUSize> SyscallArgs
    for (T1, T2, T3, T4, T5, T6)
{
    const N: usize = 6;
    fn to_usize_slice(&self) -> [usize; Self::N] {
        [
            self.0.as_usize(),
            self.1.as_usize(),
            self.2.as_usize(),
            self.3.as_usize(),
            self.4.as_usize(),
            self.5.as_usize(),
        ]
    }
}
impl<T1: AsUSize, T2: AsUSize, T3: AsUSize, T4: AsUSize, T5: AsUSize, T6: AsUSize, T7: AsUSize>
    SyscallArgs for (T1, T2, T3, T4, T5, T6, T7)
{
    const N: usize = 7;
    fn to_usize_slice(&self) -> [usize; Self::N] {
        [
            self.0.as_usize(),
            self.1.as_usize(),
            self.2.as_usize(),
            self.3.as_usize(),
            self.4.as_usize(),
            self.5.as_usize(),
            self.6.as_usize(),
        ]
    }
}
impl SyscallArgs for [usize; 7] {
    const N: usize = 7;
    fn to_usize_slice(&self) -> [usize; Self::N] {
        *self
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

    pub fn attach(&self) -> Result<()> {
        ptrace::attach(self.pid).context("Failed to attach to process")
    }

    pub fn init(&self) -> Result<()> {
        ptrace::setoptions(
            self.pid,
            ptrace::Options::PTRACE_O_TRACECLONE
                | ptrace::Options::PTRACE_O_TRACEFORK
                | ptrace::Options::PTRACE_O_TRACEVFORK
                | ptrace::Options::PTRACE_O_TRACEEXIT
                | ptrace::Options::PTRACE_O_TRACEEXEC
                | ptrace::Options::PTRACE_O_TRACESECCOMP
                | ptrace::Options::PTRACE_O_TRACESYSGOOD,
        )
        .context("Failed to set options")
    }

    pub fn deinit(&self) -> Result<()> {
        ptrace::setoptions(self.pid, ptrace::Options::empty()).context("Failed to set options")
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
            if entry.id == AT_SYSINFO_EHDR as usize {
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
    pub fn resume_syscall(&mut self) -> Result<()> {
        self._store_registers()?;
        ptrace::syscall(self.pid, None).context("Failed to ptrace-resume the child")
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
                PTRACE_GET_SYSCALL_INFO,
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
                NT_PRSTATUS as *mut c_void,
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
        ptrace::setregs(self.pid, regs.0).context("Failed to store registers of the child")
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
                NT_PRSTATUS as *mut c_void,
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
    pub fn set_syscall_no(&mut self, syscall_no: i32) -> io::Result<()> {
        self.registers_edited = true;
        self._load_registers()?.orig_rax = syscall_no as u64;
        Ok(())
    }
    #[cfg(target_arch = "aarch64")]
    pub fn set_syscall_no(&mut self, syscall_no: i32) -> io::Result<()> {
        let mut iovec = libc::iovec {
            iov_base: &syscall_no as *const _ as *mut c_void,
            iov_len: std::mem::size_of_val(&syscall_no),
        };
        if unsafe {
            libc::ptrace(
                libc::PTRACE_SETREGSET,
                self.pid.as_raw(),
                NT_ARM_SYSTEM_CALL as *mut c_void,
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

    pub fn set_syscall<Args: SyscallArgs>(&mut self, args: Args) -> io::Result<()>
    where
        [(); Args::N]:,
    {
        let slice = args.to_usize_slice();
        for (i, value) in slice.iter().skip(1).enumerate() {
            self.set_syscall_arg(i, *value)?;
        }
        self.set_syscall_no(slice[0] as i32)
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

    #[cfg(target_arch = "x86_64")]
    pub fn get_stack_pointer(&mut self) -> io::Result<usize> {
        Ok(self._load_registers()?.rsp as usize)
    }
    #[cfg(target_arch = "aarch64")]
    pub fn get_stack_pointer(&mut self) -> io::Result<usize> {
        Ok(self.get_registers()?.sp as usize)
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

    pub fn wait_for_signal(&self, signal: signal::Signal) -> Result<()> {
        let wait_status = wait::waitpid(self.pid, None).context("Failed to waitpid for process")?;
        if let wait::WaitStatus::Stopped(_, signal1) = wait_status {
            if signal == signal1 {
                return Ok(());
            }
        }
        bail!(
            "waitpid returned unexpected status at mmap: {wait_status:?}, expected signal \
             {signal:?}"
        );
    }

    pub fn exec_syscall<Args: SyscallArgs>(
        &mut self,
        args: Args,
        inside_syscall: bool,
    ) -> Result<isize>
    where
        [(); Args::N]:,
    {
        // Assuming that the instruction pointer points to a syscall instruction, execute one
        // syscall. set_syscall_no modifies orig_rax, which only makes sense after the syscall has
        // been entered.
        if !inside_syscall {
            self.set_syscall_no(-1)?;
            self.resume_syscall()?;
            self.wait_for_signal(signal::Signal::SIGTRAP)?;
        }
        self.set_syscall(args.clone())?;
        self.resume_syscall()?;
        self.wait_for_signal(signal::Signal::SIGTRAP)?;
        let result = self.get_syscall_result()? as isize;
        if result >= 0 {
            log!("<pid {}> {} = {result}", self.pid, args.debug());
            Ok(result)
        } else {
            log!(
                "<pid {}> {} = -{}",
                self.pid,
                args.debug(),
                string_table::errno_to_name(-result as i32)
            );
            Err(io::Error::from_raw_os_error(-result as i32))?
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
            SECCOMP_SET_MODE_FILTER,
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
