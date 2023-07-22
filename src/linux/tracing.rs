use anyhow::{Context, Result};
use nix::{
    libc,
    libc::{c_uint, c_void},
    sys::{ptrace, signal},
    unistd::Pid,
};
use std::ffi::CString;
use std::fs::File;
use std::io;
use std::os::unix::fs::FileExt;

pub struct TracedProcess {
    pid: Pid,
    mem: File,
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

impl TracedProcess {
    pub fn new(pid: Pid) -> Result<Self> {
        Ok(TracedProcess {
            pid,
            mem: Self::open_mem(pid)?,
        })
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

    pub unsafe fn write_word(&self, address: usize, value: usize) -> io::Result<()> {
        self.write_memory(address, &value.to_ne_bytes())
    }

    #[cfg(target_arch = "x86_64")]
    pub fn get_registers(&self) -> Result<Registers> {
        ptrace::getregs(self.pid).context("Failed to load registers of the child")
    }
    #[cfg(target_arch = "x86_64")]
    pub fn set_registers(&self, regs: Registers) -> Result<()> {
        ptrace::setregs(self.pid, regs).context("Failed to store registers of the child")
    }

    #[cfg(target_arch = "aarch64")]
    pub fn get_registers(&self) -> Result<Registers> {
        let mut data = std::mem::MaybeUninit::<Registers>::uninit();
        let mut iovec = libc::iovec {
            iov_base: data.as_mut_ptr() as *mut c_void,
            iov_len: std::mem::size_of_val(&data),
        };
        if unsafe {
            libc::ptrace(
                libc::PTRACE_GETREGSET,
                self.pid.as_raw(),
                NT_PRSTATUS as *mut c_void,
                &mut iovec,
            )
        } == -1
        {
            return Err(std::io::Error::last_os_error())
                .context("Failed to load registers of the child")?;
        }
        if iovec.iov_len < std::mem::size_of_val(&data) {
            anyhow::bail!("Failed to load registers of the child: too short register set");
        }
        unsafe { Ok(data.assume_init()) }
    }
    #[cfg(target_arch = "aarch64")]
    pub fn set_registers(&self, regs: Registers) -> Result<()> {
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
        if iovec.iov_len < std::mem::size_of_val(&regs) {
            anyhow::bail!("Failed to store registers of the child: too short register set");
        }
        Ok(())
    }

    fn get_auxiliary_vector_address(&self) -> Result<usize> {
        let word_size = std::mem::size_of::<usize>();

        let regs = self.get_registers()?;
        let mut address = get_stack_pointer(&regs);

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

    pub fn get_auxiliary_entries(&self) -> Result<Vec<AuxiliaryEntry>> {
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

    pub fn disable_vdso(&self) -> Result<()> {
        for entry in self.get_auxiliary_entries()? {
            if entry.id == AT_SYSINFO_EHDR as usize {
                unsafe { self.write_word(entry.address, libc::AT_IGNORE as usize) }
                    .context("Failed to write AT_IGNORE")?;
            }
        }
        Ok(())
    }

    pub fn resume(&self) -> Result<()> {
        ptrace::cont(self.pid, None).context("Failed to ptrace-resume the child")
    }
    pub fn resume_signal(&self, signal: signal::Signal) -> Result<()> {
        ptrace::cont(self.pid, Some(signal)).context("Failed to ptrace-resume the child")
    }
    pub fn resume_step(&self) -> Result<()> {
        ptrace::step(self.pid, None).context("Failed to ptrace-resume the child")
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
}

pub fn apply_seccomp_filter() -> Result<()> {
    let filter = include_bytes!("../../target/seccomp_filter");
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

#[cfg(target_arch = "x86_64")]
pub fn get_stack_pointer(regs: &Registers) -> usize {
    regs.rsp as usize
}
#[cfg(target_arch = "x86_64")]
pub fn set_syscall_arg(regs: &mut Registers, index: usize, arg: usize) {
    let arg = arg as u64;
    match index {
        0 => regs.rdi = arg,
        1 => regs.rsi = arg,
        2 => regs.rdx = arg,
        3 => regs.r10 = arg,
        4 => regs.r8 = arg,
        5 => regs.r9 = arg,
        _ => unimplemented!(),
    }
}
#[cfg(target_arch = "x86_64")]
pub fn set_syscall_result(regs: &mut Registers, result: usize) {
    regs.rax = result as u64;
}

#[cfg(target_arch = "aarch64")]
pub fn get_stack_pointer(regs: &Registers) -> usize {
    regs.sp as usize
}
#[cfg(target_arch = "aarch64")]
pub fn set_syscall_arg(regs: &mut Registers, index: usize, arg: usize) {
    if index < 6 {
        regs.regs[index] = arg as u64;
    } else {
        unimplemented!();
    }
}
#[cfg(target_arch = "aarch64")]
pub fn set_syscall_result(regs: &mut Registers, result: usize) {
    regs.regs[0] = result as u64;
}
