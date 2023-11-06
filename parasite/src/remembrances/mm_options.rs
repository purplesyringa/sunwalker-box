use crate::{
    anyhow::{Context, Result},
    c, file,
    fixed_vec::FixedVec,
    libc,
    util::from_str_radix,
};

#[repr(C)]
pub struct prctl_mm_map {
    start_code: usize,
    end_code: usize,
    start_data: usize,
    end_data: usize,
    start_brk: usize,
    brk: usize,
    start_stack: usize,
    arg_start: usize,
    arg_end: usize,
    env_start: usize,
    env_end: usize,
    auxv: usize,
    auxv_size: u32,
    exe_fd: u32,
}

pub fn in_orig() -> Result<prctl_mm_map> {
    let file = file::File::open(c!("/proc/self/stat")).context("Failed to open /proc/self/stat")?;

    let mut buf: FixedVec<u8, 1024> = FixedVec::new();
    file.read_into(&mut buf)
        .context("Failed to read /proc/self/stat")?;

    let pos = buf
        .iter()
        .rposition(|&c| c == b')')
        .context("Invalid stat format")?;
    let mut fields = buf[pos..].split(|&c| c == b' ').skip(2);

    for _ in 0..22 {
        fields.next().context("Invalid stat format")?;
    }
    let start_code = from_str_radix(fields.next().context("Invalid stat format")?, 10)?;
    let end_code = from_str_radix(fields.next().context("Invalid stat format")?, 10)?;
    let start_stack = from_str_radix(fields.next().context("Invalid stat format")?, 10)?;
    for _ in 0..16 {
        fields.next().context("Invalid stat format")?;
    }
    let start_data = from_str_radix(fields.next().context("Invalid stat format")?, 10)?;
    let end_data = from_str_radix(fields.next().context("Invalid stat format")?, 10)?;
    let start_brk = from_str_radix(fields.next().context("Invalid stat format")?, 10)?;
    let arg_start = from_str_radix(fields.next().context("Invalid stat format")?, 10)?;
    let arg_end = from_str_radix(fields.next().context("Invalid stat format")?, 10)?;
    let env_start = from_str_radix(fields.next().context("Invalid stat format")?, 10)?;
    let env_end = from_str_radix(fields.next().context("Invalid stat format")?, 10)?;

    Ok(prctl_mm_map {
        start_code,
        end_code,
        start_data,
        end_data,
        start_brk,
        brk: libc::brk(0)? as usize,
        start_stack,
        arg_start,
        arg_end,
        env_start,
        env_end,
        auxv: 0,
        auxv_size: 0,
        exe_fd: u32::MAX,
    })
}

pub fn in_master(map: prctl_mm_map) -> Result<()> {
    libc::prctl(
        libc::PR_SET_MM,
        libc::PR_SET_MM_MAP,
        &map,
        core::mem::size_of_val(&map),
        0,
    )?;
    Ok(())
}
