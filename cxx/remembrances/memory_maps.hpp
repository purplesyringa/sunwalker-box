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

    // We could use vmsplice here. Unfortunately, that isn't going to be zero-copy, so any
    // performance improvements are unlikely. https://lwn.net/Articles/571748/ would have fixed
    // this, but it hasn't ever been merged.

    // Don't bother checking the return value of pread64. We might get EIO or read less than
    // (end - base) bytes if a read fails because we're reading past the end of a shared mapping,
    // but the right thing to do in this case is to stop there and then.
    libc::pread64(state.orig_mem_fd, reinterpret_cast<char *>(base), end - base, base)
        .swallow(EIO, 0)
        .CONTEXT("Failed to copy memory")
        .TRY();

    if (!(prot & PROT_WRITE)) {
        libc::mprotect(base, end - base, prot & 0x7fffffff)
            .CONTEXT("Failed to remap section read-only")
            .TRY();
    }

    return {};
}

Result<void> load(const State &state, uintptr_t task_size, uintptr_t start_of_text) {
    uintptr_t hole_start = 0;

    for (size_t i = 0; i < state.count; i++) {
        const MemoryMap &map = state.maps[i];
        if (hole_start != map.base) {
            libc::munmap(hole_start, map.base - hole_start).CONTEXT("Failed to munmap hole").TRY();
        }
        if (map.base == start_of_text) {
            // Don't remap ourselves yet
        } else if ((map.flags & MAP_TYPE) == MAP_SHARED && !(map.prot & 0x80000000)) {
            // Shared maps to everything but /dev/zero can be mapped just like this
            mmap_thp(map.base, map.end - map.base, map.prot, map.flags, map.fd, map.offset)
                .CONTEXT("Failed to mmap-THP")
                .TRY();
        } else {
            map.do_map(state).TRY();
        }
        hole_start = map.end;
    }

    if (hole_start != task_size) {
        libc::munmap(hole_start, task_size - hole_start).CONTEXT("Failed to munmap hole").TRY();
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
