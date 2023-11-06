use crate::{anyhow::Result, entry::START_INFORMATION, libc};

pub fn in_master() -> Result<()> {
    if let Some(rseq) = unsafe { &START_INFORMATION.rseq_info } {
        libc::rseq(
            rseq.rseq_abi_pointer,
            rseq.rseq_abi_size,
            rseq.flags,
            rseq.signature,
        )?;
    }
    Ok(())
}

// TODO: actually restore rseq_cs and jump to abort_ip
// #[repr(C)]
// struct rseq_cs {
//     version: u32,
//     flags: u32,
//     start_ip: u64,
//     post_commit_offset: u64,
//     abort_ip: u64,
// }
