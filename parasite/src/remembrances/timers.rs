use crate::{
    anyhow::{Context, Error, Result},
    bail, c, ensure, file,
    fixed_vec::FixedVec,
    libc,
    util::{from_str_radix, heap_sort, split_once},
};

#[repr(C)]
struct sigevent {
    sigev_value: usize,
    sigev_signo: i32,
    sigev_notify: i32,
    tid: u32,
}

pub struct Timer {
    id: i32,
    signal: i32,
    sigev_value: usize,
    notify: TimerNotify,
    clock_id: isize,
}

struct TimerNotify {
    mechanism: i32,
    target: u32,
}

const SIGEV_SIGNAL: i32 = 0;
const SIGEV_NONE: i32 = 1;
const SIGEV_THREAD: i32 = 2;
const SIGEV_THREAD_ID: i32 = 4;

pub fn in_orig() -> Result<FixedVec<Timer, 64>> {
    let mut timers = FixedVec::new();
    for_each_timer(|timer| {
        timers
            .try_push(timer)
            .map_err(|_| Error::custom(libc::ENOMEM, "Too many timers"))
    })?;
    heap_sort(&mut timers, |timer| timer.id);
    Ok(timers)
}

pub fn in_fork(timers: FixedVec<Timer, 64>) -> Result<()> {
    let mut next_timer_id = 0;
    for timer in timers.as_ref() {
        while next_timer_id < timer.id {
            // Create a temporary unused timer to fill the void so that our timer gets the right ID
            add_timer(&Timer {
                id: next_timer_id,
                signal: 0,
                sigev_value: 0,
                notify: TimerNotify {
                    mechanism: SIGEV_NONE,
                    target: 0,
                },
                clock_id: libc::CLOCK_REALTIME,
            })?;
            next_timer_id += 1;
        }
        add_timer(timer)?;
        next_timer_id += 1;
    }

    // Remove temporary timers
    next_timer_id = 0;
    for timer in timers.as_ref() {
        while next_timer_id < timer.id {
            libc::timer_delete(next_timer_id)?;
            next_timer_id += 1;
        }
        next_timer_id += 1;
    }

    Ok(())
}

fn for_each_timer(mut handler: impl FnMut(Timer) -> Result<()>) -> Result<()> {
    let mut file = file::File::open(c!("/proc/self/timers"))?;
    let mut buf: file::BufReader<'_, 64> = file::BufReader::new(&mut file);

    let mut timer = None;

    for line in buf.lines() {
        let line = line?;
        if let Some((key, value)) = split_once(&line, b':') {
            match key {
                b"ID" => {
                    if let Some(timer) = timer.take() {
                        handler(timer)?;
                    }
                    timer = Some(Timer {
                        id: from_str_radix(value, 10).context("Invalid timer ID")?,
                        signal: 0,
                        sigev_value: 0,
                        notify: TimerNotify {
                            mechanism: SIGEV_NONE,
                            target: 0,
                        },
                        clock_id: 0,
                    });
                }
                b"signal" => {
                    let (signal, sigev_value) =
                        split_once(value, b'/').context("Missing / in signal entry")?;
                    let timer = timer.as_mut().context("Unexpected entry before ID")?;
                    timer.signal = from_str_radix(signal, 10).context("Invalid signal number")?;
                    timer.sigev_value =
                        from_str_radix(sigev_value, 16).context("Invalid sigev_value")?;
                }
                b"notify" => {
                    let timer = timer.as_mut().context("Unexpected entry before ID")?;
                    let (mechanism, target) =
                        split_once(value, b'/').context("Missing / in signal entry")?;
                    let mut mechanism = match mechanism {
                        b"thread" => SIGEV_THREAD,
                        b"signal" => SIGEV_SIGNAL,
                        b"none" => SIGEV_NONE,
                        _ => bail!("Invalid notification mechanism"),
                    };
                    let target = if let Some(tid) = target.strip_prefix(b"tid.") {
                        mechanism |= SIGEV_THREAD_ID;
                        from_str_radix(tid, 10).context("Invalid TID")?
                    } else if let Some(pid) = target.strip_prefix(b"pid.") {
                        from_str_radix(pid, 10).context("Invalid PID")?
                    } else {
                        bail!("Invalid notification target")
                    };
                    timer.notify = TimerNotify { mechanism, target };
                }
                b"ClockID" => {
                    let timer = timer.as_mut().context("Unexpected entry before ID")?;
                    timer.clock_id = from_str_radix(value, 10).context("Invalid clock ID")?;
                }
                _ => bail!("Invalid key"),
            }
        }
    }

    if let Some(timer) = timer.take() {
        handler(timer)?;
    }

    Ok(())
}

fn add_timer(timer: &Timer) -> Result<()> {
    let mut timer_id = 0;
    libc::timer_create(
        timer.clock_id,
        &sigevent {
            sigev_value: timer.sigev_value,
            sigev_signo: timer.signal,
            sigev_notify: timer.notify.mechanism,
            tid: timer.notify.target,
        },
        &mut timer_id,
    )?;
    ensure!(timer.id == timer_id, "Unexpected timer ID");
    Ok(())
}
