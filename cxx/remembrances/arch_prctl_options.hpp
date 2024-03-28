#include "../libc.hpp"
#include <asm/prctl.h>
#include <errno.h>

namespace arch_prctl_options {

struct State {
    long cpuid_status;
};

Result<void> save(State &state) {
    state.cpuid_status = libc::arch_prctl(ARCH_GET_CPUID, 0).CONTEXT("Failed to get cpuid").TRY();
    return {};
}

Result<void> load(const State &state) {
    // Oh, some hardware had seen the dinos and don't support faulting cpuid
    libc::arch_prctl(ARCH_SET_CPUID, state.cpuid_status)
        .swallow(ENODEV, 0)
        .CONTEXT("Failed to set cpuid")
        .TRY();
    return {};
}

} // namespace arch_prctl_options
