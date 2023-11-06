use crate::{anyhow::Result, libc};

#[repr(C)]
struct itimerval {
    it_interval: timeval,
    it_value: timeval,
}

#[repr(C)]
struct timeval {
    tv_sec: usize,
    tv_usec: usize,
}

pub struct State {
    real: itimerval,
    r#virtual: itimerval,
    prof: itimerval,
}

const ITIMER_REAL: i32 = 0;
const ITIMER_VIRTUAL: i32 = 1;
const ITIMER_PROF: i32 = 2;

// This also copies alarm(2)

pub fn in_orig() -> Result<State> {
    let mut state: State = unsafe { core::mem::zeroed() };
    libc::getitimer(ITIMER_REAL, &mut state.real)?;
    libc::getitimer(ITIMER_VIRTUAL, &mut state.r#virtual)?;
    libc::getitimer(ITIMER_PROF, &mut state.prof)?;
    Ok(state)
}

pub fn in_master(state: State) -> Result<()> {
    libc::setitimer(ITIMER_REAL, &state.real, 0)?;
    libc::setitimer(ITIMER_VIRTUAL, &state.r#virtual, 0)?;
    libc::setitimer(ITIMER_PROF, &state.prof, 0)?;
    Ok(())
}
