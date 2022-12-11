use anyhow::{Context, Result};
use nix::{
    libc,
    libc::c_void,
    sys::{ptrace, signal},
    unistd::Pid,
};

pub struct StartingProcess {
    pid: Pid,
}

pub struct AuxiliaryEntry {
    pub address: usize,
    pub id: usize,
    pub value: usize,
}

const AT_SYSINFO_EHDR: u64 = 33; // x86-64

impl StartingProcess {
    pub fn new(pid: Pid) -> Self {
        StartingProcess { pid }
    }

    fn read_word(&self, address: usize) -> Result<usize> {
        ptrace::read(self.pid, address as *mut c_void)
            .map(|x| x as usize)
            .context("Failed to read word")
    }

    unsafe fn write_word(&self, address: usize, value: usize) -> Result<()> {
        ptrace::write(self.pid, address as *mut c_void, value as *mut c_void)
            .context("Failed to write word")
    }

    fn get_auxiliary_vector_address(&self) -> Result<usize> {
        let word_size = std::mem::size_of::<usize>();

        let regs = ptrace::getregs(self.pid).context("Failed to load registers of the child")?;
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
            println!("entry {} {}", entry.id, entry.value);
            if entry.id == AT_SYSINFO_EHDR as usize {
                println!("patch");
                assert!(self.read_word(entry.address)? == AT_SYSINFO_EHDR as usize);
                unsafe {
                    self.write_word(entry.address, libc::AT_IGNORE as usize)?;
                }
                assert!(self.read_word(entry.address)? == libc::AT_IGNORE as usize);
            }
        }
        Ok(())
    }

    pub fn detach(&self) -> Result<()> {
        ptrace::detach(self.pid, None).context("Failed to ptrace-detach from child")
    }

    pub fn resume(&self) -> Result<()> {
        ptrace::cont(self.pid, None).context("Failed to ptrace-resume the child")
    }
    pub fn resume_signal(&self, signal: signal::Signal) -> Result<()> {
        ptrace::cont(self.pid, Some(signal)).context("Failed to ptrace-resume the child")
    }
}
