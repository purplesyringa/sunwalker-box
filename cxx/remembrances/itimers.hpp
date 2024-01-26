#include "../libc.hpp"
#include "../result.hpp"
#include <sys/time.h>

namespace itimers {

struct State {
    itimerval real;
    itimerval virtual_;
    itimerval prof;
};

Result<void> save(State &state) {
    // This also saves alarm(2)
    libc::getitimer(ITIMER_REAL, &state.real).CONTEXT("Failed to get ITIMER_REAL").TRY();
    libc::getitimer(ITIMER_VIRTUAL, &state.virtual_).CONTEXT("Failed to get ITIMER_VIRTUAL").TRY();
    libc::getitimer(ITIMER_PROF, &state.prof).CONTEXT("Failed to get ITIMER_PROF").TRY();
    return {};
}

Result<void> load(const State &state) {
    libc::setitimer(ITIMER_REAL, &state.real, nullptr).CONTEXT("Failed to set ITIMER_REAL").TRY();
    libc::setitimer(ITIMER_VIRTUAL, &state.virtual_, nullptr)
        .CONTEXT("Failed to set ITIMER_VIRTUAL")
        .TRY();
    libc::setitimer(ITIMER_PROF, &state.prof, nullptr).CONTEXT("Failed to set ITIMER_PROF").TRY();
    return {};
}

} // namespace itimers
