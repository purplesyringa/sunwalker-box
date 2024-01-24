#include "../libc.hpp"
#include <asm/prctl.h>
#include <errno.h>

namespace arch_prctl_options {

struct State {
    long fs_base;
    long gs_base;
    long cpuid_status;
};

static Result<void> save(State &state) {
    libc::arch_prctl(ARCH_GET_FS, reinterpret_cast<unsigned long>(&state.fs_base))
        .CONTEXT("Failed to get fsbase")
        .TRY();
    libc::arch_prctl(ARCH_GET_GS, reinterpret_cast<unsigned long>(&state.gs_base))
        .CONTEXT("Failed to get gsbase")
        .TRY();
    state.cpuid_status = libc::arch_prctl(ARCH_GET_CPUID, 0).CONTEXT("Failed to get cpuid").TRY();
    return {};
}

static Result<void> load(const State &state) {
    libc::arch_prctl(ARCH_SET_FS, state.fs_base).CONTEXT("Failed to set fsbase").TRY();
    libc::arch_prctl(ARCH_SET_GS, state.gs_base).CONTEXT("Failed to set gsbase").TRY();
    // Oh, some hardware had seen the dinos and don't support faulting cpuid
    libc::arch_prctl(ARCH_SET_CPUID, state.cpuid_status)
        .swallow(ENODEV, 0)
        .CONTEXT("Failed to set cpuid")
        .TRY();
    return {};
}

} // namespace arch_prctl_options
