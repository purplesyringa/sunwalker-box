use anyhow::{Context, Result};
use nix::{
    libc,
    libc::{c_uint, c_void},
    sys::{ptrace, signal},
    unistd::Pid,
};

pub struct TracedProcess {
    pid: Pid,
}

pub struct AuxiliaryEntry {
    pub address: usize,
    pub id: usize,
    pub value: usize,
}

const AT_SYSINFO_EHDR: u64 = 33; // x86-64
const SECCOMP_SET_MODE_FILTER: c_uint = 1;
const PTRACE_GET_SYSCALL_INFO: i32 = 0x420e;

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

impl TracedProcess {
    pub fn new(pid: Pid) -> Self {
        TracedProcess { pid }
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

    pub fn read_word(&self, address: usize) -> Result<usize> {
        ptrace::read(self.pid, address as *mut c_void)
            .map(|x| x as usize)
            .context("Failed to read word")
    }

    pub unsafe fn write_word(&self, address: usize, value: usize) -> Result<()> {
        ptrace::write(self.pid, address as *mut c_void, value as *mut c_void)
            .context("Failed to write word")
    }

    pub fn get_registers(&self) -> Result<libc::user_regs_struct> {
        ptrace::getregs(self.pid).context("Failed to load registers of the child")
    }
    pub fn set_registers(&self, regs: libc::user_regs_struct) -> Result<()> {
        ptrace::setregs(self.pid, regs).context("Failed to store registers of the child")
    }

    fn get_auxiliary_vector_address(&self) -> Result<usize> {
        let word_size = std::mem::size_of::<usize>();

        let regs = self.get_registers()?;
        let mut address = regs.rsp as usize;

        // Skip argc & argv
        let argc = self.read_word(address)?;
        address += word_size;
        address += (argc + 1) * word_size;

        // Skip environment
        while self.read_word(address)? != 0 {
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
            let id = self.read_word(address)?;
            address += word_size;
            let value = self.read_word(address)?;
            address += word_size;
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
                unsafe {
                    self.write_word(entry.address, libc::AT_IGNORE as usize)?;
                }
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
