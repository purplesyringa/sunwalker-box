use crate::linux::string_table;
use anyhow::{Context, Result};
use nix::{
    errno::Errno,
    libc,
    libc::{c_uint, c_void},
    sys::ptrace,
    unistd::Pid,
};
use std::ffi::CString;
use std::fmt::Write;
use std::fs::File;
use std::io;
use std::os::unix::fs::FileExt;

pub struct TracedProcess {
    pid: Pid,
    mem: File,
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
#[derive(Clone)]
pub struct user_pt_regs {
    pub regs: [u64; 31],
    pub sp: u64,
    pub pc: u64,
    pub pstate: u64,
}

#[cfg(target_arch = "x86_64")]
pub type Registers = libc::user_regs_struct;
#[cfg(target_arch = "aarch64")]
pub type Registers = user_pt_regs;

pub trait SyscallArgs {
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

impl TracedProcess {
    pub fn new(pid: Pid) -> Result<Self> {
        Ok(TracedProcess {
            pid,
            mem: Self::open_mem(pid)?,
            cached_registers: None,
            registers_edited: false,
        })
    }

    pub fn get_pid(&self) -> Pid {
        self.pid
    }

    pub fn reload_mm(&mut self) -> Result<()> {
        self.mem = Self::open_mem(self.pid)?;
        Ok(())
    }

    fn open_mem(pid: Pid) -> Result<File> {
        File::options()
            .read(true)
            .write(true)
            .open(format!("/proc/{pid}/mem"))
            .with_context(|| format!("Failed to open /proc/{pid}/mem"))
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

    pub fn read_memory(&self, address: usize, buf: &mut [u8]) -> io::Result<()> {
        self.mem.read_exact_at(buf, address as u64)
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
            let n_read = self.mem.read_at(&mut buf[offset..], address as u64)?;
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
        self.mem.write_all_at(buf, address as u64)
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
        ptrace::getregs(pid)
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
        ptrace::setregs(self.pid, regs).context("Failed to store registers of the child")
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
            let regs = self.cached_registers.take().unwrap();
            self._set_registers(regs?)?;
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
}

pub fn apply_seccomp_filter() -> Result<()> {
    let filter = include_bytes!("../../target/filter.seccomp.out");
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
