use anyhow::{Context, Result};
use nix::{
    libc,
    libc::c_void,
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
                | ptrace::Options::PTRACE_O_TRACEEXEC,
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

    pub fn get_signal_info(&self) -> Result<libc::siginfo_t> {
        ptrace::getsiginfo(self.pid).context("Failed to get signal info")
    }
    pub fn get_event_msg(&self) -> Result<libc::c_long> {
        ptrace::getevent(self.pid).context("Failed to get event")
    }
}
