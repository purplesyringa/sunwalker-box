#include "../libc.hpp"

namespace itimers {

struct State {
    __kernel_old_itimerval real;
    __kernel_old_itimerval virtual_;
    __kernel_old_itimerval prof;
};

Result<void> save(State &state) {
    // This also saves alarm(2)
    libc::getitimer(ITIMER_REAL, &state.real).CONTEXT("Failed to get ITIMER_REAL").TRY();
    libc::getitimer(ITIMER_VIRTUAL, &state.virtual_).CONTEXT("Failed to get ITIMER_VIRTUAL").TRY();
    libc::getitimer(ITIMER_PROF, &state.prof).CONTEXT("Failed to get ITIMER_PROF").TRY();
    return {};
}

Result<void> load(const State &state) {
    libc::setitimer(ITIMER_REAL, const_cast<__kernel_old_itimerval *>(&state.real), nullptr)
        .CONTEXT("Failed to set ITIMER_REAL")
        .TRY();
    libc::setitimer(ITIMER_VIRTUAL, const_cast<__kernel_old_itimerval *>(&state.virtual_), nullptr)
        .CONTEXT("Failed to set ITIMER_VIRTUAL")
        .TRY();
    libc::setitimer(ITIMER_PROF, const_cast<__kernel_old_itimerval *>(&state.prof), nullptr)
        .CONTEXT("Failed to set ITIMER_PROF")
        .TRY();
    return {};
}

} // namespace itimers
