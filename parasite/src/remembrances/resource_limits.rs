use crate::{anyhow::Result, entry::START_INFORMATION, libc};

#[repr(C)]
struct rlimit {
    rlim_cur: u64,
    rlim_max: u64,
}

const RLIMIT_CPU: i32 = 0;
const RLIMIT_FSIZE: i32 = 1;
const RLIMIT_DATA: i32 = 2;
const RLIMIT_STACK: i32 = 3;
// const RLIMIT_CORE: i32 = 4;
// const RLIMIT_RSS: i32 = 5;
const RLIMIT_NOFILE: i32 = 7;
const RLIMIT_AS: i32 = 9;
const RLIMIT_NPROC: i32 = 6;
const RLIMIT_MEMLOCK: i32 = 8;
const RLIMIT_LOCKS: i32 = 10;
const RLIMIT_SIGPENDING: i32 = 11;
const RLIMIT_MSGQUEUE: i32 = 12;
const RLIMIT_NICE: i32 = 13;
const RLIMIT_RTPRIO: i32 = 14;
const RLIMIT_RTTIME: i32 = 15;

pub fn in_master() -> Result<()> {
    // Ignore:
    // - RLIMIT_CORE, as we disable core dumps in the controller,
    // - RLIMIT_RSS, which does nothing in modern kernels.
    // TODO: RLIMIT_CPU is likely to be reset after manually forking the process and has to be
    // updated or spent
    // TODO: Reset user-specific limits after the process is run so that they are not applied to
    // other runs
    for resource in [
        RLIMIT_AS,
        RLIMIT_CPU,
        RLIMIT_DATA,
        RLIMIT_FSIZE,
        RLIMIT_LOCKS,
        RLIMIT_MEMLOCK,
        RLIMIT_MSGQUEUE,
        RLIMIT_NICE,
        RLIMIT_NOFILE,
        RLIMIT_NPROC,
        RLIMIT_RTPRIO,
        RLIMIT_RTTIME,
        RLIMIT_SIGPENDING,
        RLIMIT_STACK,
    ] {
        let mut limit = rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        libc::prlimit64(
            unsafe { START_INFORMATION.orig_pid },
            resource,
            0,
            &mut limit,
        )?;
        libc::prlimit64(0, resource, &limit, 0)?;
    }

    Ok(())
}
