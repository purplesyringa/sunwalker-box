#include "../libc.hpp"
#include "../result.hpp"
#include <asm/errno.h>
#include <linux/mman.h>
#include <linux/prctl.h>

namespace memory_maps {

// Use the default value of sysctl vm.max_map_count
static constexpr size_t MAX_MEMORY_MAPS = 65530;

__attribute__((always_inline)) inline Result<void> mmap_thp(uintptr_t base, size_t length, int prot,
                                                            int flags, int fd, off_t offset) {
    // We want THP, because we're going to clone lots of page tables, and they better be small. The
    // "correct" solution is enabling THP in "always" mode as opposed to "madvise" system-wide, but
    // let's at least try to handle the worse case gracefully
    // FIXME: This is only valid for x86-64
    libc::mmap(base, length, prot, flags, fd, offset).CONTEXT("Failed to mmap section").TRY();
    libc::madvise(base, length, MADV_HUGEPAGE).CONTEXT("Failed to madvise huge pages").TRY();
    return {};
}

struct MemoryMap {
    uintptr_t base;
    uintptr_t end;
    int prot;
    int flags;
    int fd;
    off_t offset;

    __attribute__((always_inline)) inline Result<void> do_map(int orig_mem_fd) const {
        mmap_thp(base, end - base, (prot & 0x7fffffff) | PROT_WRITE, flags, fd, offset)
            .CONTEXT("Failed to mmap section")
            .TRY();

        // We could use vmsplice here. Unfortunately, that isn't going to be zero-copy, so any
        // performance improvements are unlikely. https://lwn.net/Articles/571748/ would have fixed
        // this, but it hasn't ever been merged
        uintptr_t cur_base = base;
        while (cur_base < end) {
            cur_base += libc::pread64(orig_mem_fd, reinterpret_cast<char *>(cur_base),
                                      end - cur_base, cur_base)
                            .CONTEXT("Failed to read memory from original process")
                            .TRY();
        }

        if (!(prot & PROT_WRITE)) {
            libc::mprotect(base, end - base, prot & 0x7fffffff)
                .CONTEXT("Failed to remap section read-only")
                .TRY();
        }

        return {};
    }
};

struct State {
    int orig_mem_fd;
    size_t count;
    std::array<MemoryMap, MAX_MEMORY_MAPS> maps;
};

static Result<void> load_before_fork(const State &state) {
    for (size_t i = 0; i < state.count; i++) {
        const MemoryMap &map = state.maps[i];
        if (map.prot == -1) {
            // Start of [vvar]
            libc::arch_prctl(ARCH_MAP_VDSO_64, map.base).CONTEXT("Failed to mmap vdso").TRY();
            continue;
        }

        if ((map.flags & MAP_TYPE) == MAP_PRIVATE) {
            map.do_map(state.orig_mem_fd).TRY();
        } else if (!(map.prot & 0x80000000)) {
            // Shared maps to everything but /dev/zero can be mapped just like this
            mmap_thp(map.base, map.end - map.base, map.prot, map.flags, map.fd, map.offset)
                .CONTEXT("Failed to mmap section")
                .TRY();
        }
    }

    return {};
}

static Result<void> load_after_fork(const State &state) {
    for (size_t i = 0; i < state.count; i++) {
        const MemoryMap &map = state.maps[i];
        if ((map.flags & MAP_TYPE) == MAP_SHARED && (map.prot & 0x80000000)) {
            map.do_map(state.orig_mem_fd).TRY();
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
