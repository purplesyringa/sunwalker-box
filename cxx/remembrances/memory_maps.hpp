#include "../libc.hpp"
#include "../result.hpp"
#include <asm/errno.h>
#include <linux/mman.h>
#include <linux/prctl.h>

namespace memory_maps {

// Use the default value of sysctl vm.max_map_count
static constexpr size_t MAX_MEMORY_MAPS = 65530;

Result<void> mmap_thp(uintptr_t base, size_t length, int prot, int flags, int fd, off_t offset) {
    // We want THP, because we're going to clone lots of page tables, and they better be small. The
    // "correct" solution is enabling THP in "always" mode as opposed to "madvise" system-wide, but
    // let's at least try to handle the worse case gracefully
    libc::mmap(base, length, prot, flags, fd, offset).CONTEXT("Failed to mmap section").TRY();
    // If kernel is built without CONFIG_TRANSPARENT_HUGEPAGE, like `linux-rt` in Arch Linux,
    // madvise THP will return EINVAL. We can't do anything about it and will just swallow the error
    libc::madvise(base, length, MADV_HUGEPAGE)
        .swallow(EINVAL, 0)
        .CONTEXT("Failed to madvise huge pages")
        .TRY();
    return {};
}

// This is adapted from UAPI
const uint64_t PM_MMAP_EXCLUSIVE = 1ULL << 56;
const uint64_t PM_FILE = 1ULL << 61;
const uint64_t PM_SWAP = 1ULL << 62;
const uint64_t PM_PRESENT = 1ULL << 63;

std::array<uint64_t, 8192> pagemap_entries;

struct State;

struct MemoryMap {
    uintptr_t base;
    uintptr_t end;
    int prot;
    int flags;
    int fd;
    off_t offset;

    // This function is not supposed to be invoked for shared file-backed mappings.
    Result<void> do_map(const State &state) const;
};

struct State {
    int orig_mem_fd;
    int orig_pagemap_fd;
    size_t count;
    std::array<MemoryMap, MAX_MEMORY_MAPS> maps;
};

Result<void> MemoryMap::do_map(const State &state) const {
    mmap_thp(base, end - base, (prot & 0x7fffffff) | PROT_WRITE, flags, fd, offset)
        .CONTEXT("Failed to mmap-THP")
        .TRY();

// XXX: FUCK YOU ALISA
#define page_size 4096

    static uintptr_t cur_base, region_start, region_end;
    cur_base = base;
    region_start = base;
    region_end = base;

    auto try_read = [&]() -> Result<void> {
        if (region_start == region_end) {
            return {};
        }
        // We could use vmsplice here. Unfortunately, that isn't going to be zero-copy, so any
        // performance improvements are unlikely. https://lwn.net/Articles/571748/ would have fixed
        // this, but it hasn't ever been merged.
        size_t n_read = libc::pread64(state.orig_mem_fd, reinterpret_cast<char *>(region_start),
                                      region_end - region_start, region_start)
                            .CONTEXT("Failed to copy memory")
                            .TRY();
        ENSURE(n_read == region_end - region_start, "Unexpected read size");
        return {};
    };

    while (cur_base < end) {
        size_t n_entries =
            libc::pread64(state.orig_pagemap_fd, reinterpret_cast<char *>(pagemap_entries.data()),
                          std::min(pagemap_entries.size(), (end - cur_base) / page_size) * 8,
                          cur_base / page_size * 8)
                .CONTEXT("Failed to read pagemap")
                .TRY();
        n_entries /= 8;
        ENSURE(n_entries > 0, "Nothing could be read from pagemap");

        static size_t i;
        for (i = 0; i < n_entries; i++) {
            uint64_t entry = pagemap_entries[i];

            // Detect if 'entry' points at a page we should copy (and not skip).
            bool should_copy_page;
            if ((flags & MAP_TYPE) == MAP_SHARED) {
                // This function is never called for shared file-backed mappings. Therefore,
                // each untouched page is necessarily zero and we can skip it. Touched pages,
                // i.e. those present or swapped, are *always* allocated because that's how
                // shared memory works; it's basically copy-on-read as opposed to copy-on-write.
                should_copy_page = entry & (PM_SWAP | PM_PRESENT);
            } else {
                // In private mappings, a present page does not indicate it was *allocated*, it
                // could just point at page cache or a zero page. We don't want to lose this
                // deduplication, so we have to invent another way to detect if the page was
                // modified.
                if (prot & 0x80000000) {
                    // Modified pages will be exclusive, while the zero pages won't
                    should_copy_page = entry & (PM_SWAP | PM_MMAP_EXCLUSIVE);
                } else {
                    // Modified pages will be anonymous, while the file-backed pages won't
                    should_copy_page = !(entry & PM_FILE);
                }
            }

            if (!should_copy_page || region_end != cur_base) {
                try_read().TRY();
                region_start = cur_base;
                region_end = cur_base;
            }

            cur_base += page_size;

            if (should_copy_page) {
                region_end = cur_base;
            }
        }
    }

    try_read().TRY();

    if (!(prot & PROT_WRITE)) {
        libc::mprotect(base, end - base, prot & 0x7fffffff)
            .CONTEXT("Failed to remap section read-only")
            .TRY();
    }

    return {};
}

Result<void> load_before_fork(const State &state) {
    for (size_t i = 0; i < state.count; i++) {
        const MemoryMap &map = state.maps[i];
        if ((map.flags & MAP_TYPE) == MAP_PRIVATE) {
            map.do_map(state).TRY();
        } else if (!(map.prot & 0x80000000)) {
            // Shared maps to everything but /dev/zero can be mapped just like this
            mmap_thp(map.base, map.end - map.base, map.prot, map.flags, map.fd, map.offset)
                .CONTEXT("Failed to mmap-THP")
                .TRY();
        }
    }

    return {};
}

Result<void> load_after_fork(const State &state) {
    for (size_t i = 0; i < state.count; i++) {
        const MemoryMap &map = state.maps[i];
        if ((map.flags & MAP_TYPE) == MAP_SHARED && (map.prot & 0x80000000)) {
            map.do_map(state).TRY();
        }
    }

    // Close fds
    libc::close(state.orig_mem_fd).CONTEXT("Failed to close fd").TRY();

    for (size_t i = 0; i < state.count; i++) {
        const MemoryMap &map = state.maps[i];
        if (map.fd != -1) {
            // Ignore EBADF. It may arise if two mappings share an fd. We could keep track of what
            // fds we've removed, but we choose to use simpler code
            libc::close(map.fd).swallow(EBADF, 0).CONTEXT("Failed to close fd").TRY();
        }
    }

    return {};
}

} // namespace memory_maps
