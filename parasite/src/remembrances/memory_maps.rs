use crate::{
    anyhow::{Context, Error, Result},
    ensure,
    entry::START_INFORMATION,
    file,
    fixed_vec::FixedVec,
    format, libc,
    util::from_str_radix,
};
use core::ffi::CStr;

#[derive(PartialEq)]
enum SegmentType {
    Simple,
    Stack,
    Vdso,
    Vsyscall,
    Vvar,
}

struct MemoryMap<'a> {
    pid: Option<u32>,
    base_str: &'a [u8],
    end_str: &'a [u8],
    prot: isize,
    shared: bool,
    offset_str: &'a [u8],
    dev_str: [u8; 5],
    inode_str: &'a [u8],
    segment_type: SegmentType,
}

impl MemoryMap<'_> {
    fn base(&self) -> Result<usize> {
        from_str_radix(self.base_str, 16)
    }
    fn end(&self) -> Result<usize> {
        from_str_radix(self.end_str, 16)
    }
    fn offset(&self) -> Result<u64> {
        from_str_radix(self.offset_str, 16)
    }
    fn major(&self) -> Result<u8> {
        from_str_radix(&self.dev_str[..2], 16)
    }
    fn minor(&self) -> Result<u8> {
        from_str_radix(&self.dev_str[3..], 16)
    }
    fn inode(&self) -> Result<u64> {
        from_str_radix(self.inode_str, 10)
    }

    fn get_map_files_path(&self) -> FixedVec<u8, 61> {
        format!(
            b"/proc/",
            {either} match self.pid {
                Some(pid) => Left(pid),
                None => Right(b"self"),
            },
            b"/map_files/",
            {<= 16} self.base_str,
            b"-",
            {<= 16} self.end_str,
            b"\0",
        )
    }
}

struct SavedMapping {
    base: usize,
    end: usize,
    prot: isize,
}

pub struct Saved {
    mem: file::File,
    shared_mappings: FixedVec<SavedMapping, 16>,
    executable_mappings: FixedVec<SavedMapping, 16>,
}

pub fn in_master() -> Result<Saved> {
    unmap_garbage()?;

    let mem_path = format!(b"/proc/", unsafe { START_INFORMATION.orig_pid }, b"/mem\0");
    let mem_path = unsafe { CStr::from_bytes_with_nul_unchecked(&mem_path) };
    let mem = file::File::open(mem_path).context("Failed to open /proc/pid/mem")?;

    let mut last_fd_key = (0, 0, 0);
    let mut last_fd = -1;

    let mut shared_mappings = FixedVec::new();
    let mut executable_mappings = FixedVec::new();

    for_each_map(Some(unsafe { START_INFORMATION.orig_pid }), |map| {
        // This segment has the same address in all processes
        if map.segment_type == SegmentType::Vsyscall {
            return Ok(());
        }
        // This segment is mapped as a part of ARCH_MAP_VDSO_64
        if map.segment_type == SegmentType::Vdso {
            return Ok(());
        }

        let base = map.base()?;

        // Skip ourselves
        if base == unsafe { START_INFORMATION.relocate_to } {
            return Ok(());
        }

        // [vvar] and [vdso] are handled manually
        // FIXME: one could theoretically unmap a part of [vvar]/[vdso], which we don't replicate
        // correctly
        if map.segment_type == SegmentType::Vvar {
            const ARCH_MAP_VDSO_64: i32 = 0x2003;
            libc::arch_prctl(ARCH_MAP_VDSO_64, base)?;
            return Ok(());
        }

        let end = map.end()?;

        if map.shared {
            // Shared memory is always backed by a writable file (anonymous mappings are backed by
            // /dev/zero), of which we only allow a short idempotent whitelist. Out of those,
            // /dev/zero is the only file that can be mmap'ed. Therefore, we can just mmap (and
            // populate) shared memory on every fork.

            // One problem is that two virtual addresses can be mmapped to the same physical
            // address, e.g. if we do memfd_create() and then mmap() it at two addresses. Luckily,
            // we have disabled memfd_create() in prefork mode, so that doesn't bother us.

            // TODO: handle non-zero offset
            shared_mappings
                .try_push(SavedMapping {
                    base,
                    end,
                    prot: map.prot,
                })
                .map_err(|_| Error::custom(libc::ENOMEM, "Too many shared mappings"))?;
        } else {
            let mut flags = libc::MAP_FIXED_NOREPLACE | libc::MAP_PRIVATE;
            if map.segment_type == SegmentType::Stack {
                // FIXME: This assumes that a) only [stack] uses MAP_GROWSDOWN, b) no one has
                // disabled MAP_GROWSDOWN on [stack]. This is the case for most runtimes, but is
                // horrendously broken. We should parse /proc/<pid>/smaps instead. The same applies
                // to MAP_STACK. Also, they say that MAP_GROWSDOWN'ing a new page is not quite the
                // same thing as what the kernel does when allocating the main stack, so we should
                // figure that out.
                flags |= libc::MAP_GROWSDOWN | libc::MAP_STACK;
            }

            let inode = map.inode()?;

            let fd;
            if inode == 0 {
                fd = -1;
                flags |= libc::MAP_ANONYMOUS;
            } else {
                // Don't open many fd's to one file for efficiency
                let key = (inode, map.major()?, map.minor()?);
                if key != last_fd_key {
                    if last_fd != -1 {
                        libc::close(last_fd)?;
                    }
                    last_fd_key = key;
                    let path = map.get_map_files_path();
                    last_fd = libc::open(path.as_ref(), libc::O_RDONLY | libc::O_CLOEXEC)?;
                }
                fd = last_fd;
            }

            // Map memory
            libc::mmap(
                base,
                end - base,
                libc::PROT_READ | libc::PROT_WRITE, // for pread64
                flags,
                fd,
                map.offset()?,
            )?;

            // Fill with data
            populate_region(mem.as_raw_fd(), base, end)?;

            // Fix page protection
            // Don't grant PROT_EXEC before dropping permissions so that we don't accidentally
            // execute user code under real root. Oof.
            if map.prot & !libc::PROT_EXEC != libc::PROT_READ | libc::PROT_WRITE {
                libc::mprotect(base, end - base, map.prot & !libc::PROT_EXEC)?;
            }
            if map.prot & libc::PROT_EXEC != 0 {
                executable_mappings
                    .try_push(SavedMapping {
                        base,
                        end,
                        prot: map.prot,
                    })
                    .map_err(|_| Error::custom(libc::ENOMEM, "Too many executable mappings"))?;
            }
        }

        Ok(())
    })?;

    if last_fd != -1 {
        libc::close(last_fd)?;
    }

    Ok(Saved {
        mem,
        shared_mappings,
        executable_mappings,
    })
}

pub fn in_fork(saved: Saved) -> Result<()> {
    for map in saved.shared_mappings.as_ref() {
        libc::mmap(
            map.base,
            map.end - map.base,
            libc::PROT_READ | libc::PROT_WRITE, // for pread64
            libc::MAP_FIXED_NOREPLACE | libc::MAP_SHARED,
            -1,
            0,
        )?;
        populate_region(saved.mem.as_raw_fd(), map.base, map.end)?;
        libc::mprotect(map.base, map.end - map.base, map.prot)?;
    }

    for map in saved.executable_mappings.as_ref() {
        libc::mprotect(map.base, map.end - map.base, map.prot)?;
    }

    Ok(())
}

fn populate_region(mem_fd: i32, mut base: usize, end: usize) -> Result<()> {
    while base != end {
        let n_read =
            libc::pread64(mem_fd, base, end - base, base).context("Failed to populate region")?;
        if n_read == 0 {
            return Err(Error::custom(
                libc::EFAULT,
                "pread64 failed in the middle of a region",
            ));
        }
        base += n_read as usize;
    }
    Ok(())
}

fn unmap_garbage() -> Result<()> {
    for_each_map(None, |map| {
        // Unmap everything but ourselves and non-unmappable segments
        if map.segment_type != SegmentType::Simple && map.segment_type != SegmentType::Vsyscall {
            let base = map.base()?;
            let end = map.end()?;
            libc::munmap(base, end - base)?;
        }
        Ok(())
    })
}

fn for_each_map(pid: Option<u32>, mut handler: impl FnMut(MemoryMap) -> Result<()>) -> Result<()> {
    let path = format!(
        b"/proc/",
        {either} match pid {
            Some(pid) => Left(pid),
            None => Right(b"self"),
        },
        b"/maps\0",
    );
    let path = unsafe { CStr::from_bytes_with_nul_unchecked(&path) };
    let mut maps = file::File::open(path).context("Failed to open /proc/pid/maps")?;

    let mut buf: file::BufReader<'_, 128> = file::BufReader::new(&mut maps);

    for line in buf.lines() {
        let line = line.context("Failed to read /proc/pid/maps")?;

        let mut truncated_base_start = 0;
        while line.get(truncated_base_start) == Some(&b'0') {
            truncated_base_start += 1;
        }
        ensure!(truncated_base_start < line.len(), "Invalid maps format");

        let mut base_end = truncated_base_start;
        while base_end < line.len() && line[base_end] != b'-' {
            base_end += 1;
        }
        ensure!(base_end < line.len(), "Invalid maps format");
        ensure!(base_end - truncated_base_start <= 16, "Invalid maps format");

        if truncated_base_start == base_end {
            ensure!(truncated_base_start > 0, "Invalid maps format");
            truncated_base_start -= 1;
        }

        let mut truncated_end_start = base_end + 1;
        while line.get(truncated_end_start) == Some(&b'0') {
            truncated_end_start += 1;
        }

        let mut end_end = truncated_end_start;
        while end_end < line.len() && line[end_end] != b' ' {
            end_end += 1;
        }
        ensure!(end_end < line.len(), "Invalid maps format");
        ensure!(end_end - truncated_end_start <= 16, "Invalid maps format");

        let prot_start = end_end + 1;
        let prot_end = prot_start + 4;
        let prot = line
            .get(prot_start..prot_end)
            .context("Invalid maps format")?;
        let shared = prot[3] == b's';
        let mut prot = if prot[0] == b'r' { libc::PROT_READ } else { 0 }
            | if prot[1] == b'w' { libc::PROT_WRITE } else { 0 }
            | if prot[2] == b'x' { libc::PROT_EXEC } else { 0 };
        if prot == 0 {
            prot = libc::PROT_NONE;
        }

        let offset_start = prot_end + 1;
        let mut offset_end = offset_start;
        while offset_end < line.len() && line[offset_end] != b' ' {
            offset_end += 1;
        }
        ensure!(offset_end < line.len(), "Invalid maps format");

        let dev_start = offset_end + 1;
        let dev_end = dev_start + 5;
        ensure!(line.get(dev_end) == Some(&b' '), "Invalid maps format");
        let mut dev_str = [0u8; 5];
        dev_str.copy_from_slice(unsafe { line.slice_unchecked(dev_start..dev_end) });
        ensure!(dev_str[2] == b':', "Invalid maps format");

        let inode_start = dev_end + 1;
        let mut inode_end = inode_start;
        while inode_end < line.len() && line[inode_end] != b' ' {
            inode_end += 1;
        }
        ensure!(inode_end - inode_start <= 16, "Invalid maps format");

        let mut desc_start = inode_end;
        while line.get(desc_start) == Some(&b' ') {
            desc_start += 1;
        }
        let desc = unsafe { line.slice_unchecked(desc_start..line.len()) };

        let segment_type = match desc {
            b"[stack]\n" => SegmentType::Stack,
            b"[vdso]\n" => SegmentType::Vdso,
            b"[vsyscall]\n" => SegmentType::Vsyscall,
            b"[vvar]\n" => SegmentType::Vvar,
            _ => SegmentType::Simple,
        };

        handler(MemoryMap {
            pid,
            base_str: unsafe { line.slice_unchecked(truncated_base_start..base_end) },
            end_str: unsafe { line.slice_unchecked(truncated_end_start..end_end) },
            prot,
            shared,
            offset_str: unsafe { line.slice_unchecked(offset_start..offset_end) },
            dev_str,
            inode_str: unsafe { line.slice_unchecked(inode_start..inode_end) },
            segment_type,
        })?;
    }

    Ok(())
}
