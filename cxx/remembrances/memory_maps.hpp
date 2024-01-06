#include "../libc.hpp"
#include "../result.hpp"
#include <asm/errno.h>
#include <linux/mman.h>
#include <linux/prctl.h>

namespace memory_maps {

// Use the default value of sysctl vm.max_map_count
static constexpr size_t MAX_MEMORY_MAPS = 65530;

struct MemoryMap {
    uintptr_t base;
    uintptr_t end;
    int prot;
    int flags;
    int fd;
    off_t offset;
};

struct State {
    int orig_mem_fd;
    size_t count;
    std::array<MemoryMap, MAX_MEMORY_MAPS> maps;
};

static Result<void> load(const State &state) {
    for (size_t i = 0; i < state.count; i++) {
        const MemoryMap &map = state.maps[i];

        if (map.prot == -1) {
            // Start of [vvar]
            libc::arch_prctl(ARCH_MAP_VDSO_64, map.base).CONTEXT("Failed to mmap vdso").TRY();
            continue;
        }

        libc::mmap(map.base, map.end - map.base, map.prot | PROT_WRITE, map.flags, map.fd,
                   map.offset)
            .CONTEXT("Failed to mmap section")
            .TRY();

        // We could use vmsplice here. Unfortunately, that isn't going to be zero-copy, so any
        // performance improvements are unlikely. https://lwn.net/Articles/571748/ would have fixed
        // this, but it hasn't ever been merged
        uintptr_t cur_base = map.base;
        while (cur_base < map.end) {
            cur_base += libc::pread64(state.orig_mem_fd, reinterpret_cast<char *>(cur_base),
                                      map.end - cur_base, cur_base)
                            .CONTEXT("Failed to read memory from original process")
                            .TRY();
        }

        if (!(map.prot & PROT_WRITE)) {
            libc::mprotect(map.base, map.end - map.base, map.prot)
                .CONTEXT("Failed to remap section read-only")
                .TRY();
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
