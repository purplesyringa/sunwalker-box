#include "../libc.hpp"
#include <array>

namespace signal_handlers {

using State = std::array<struct sigaction, 64>;

static Result<void> save(State &state) {
    for (int signum = 1; signum <= 64; signum++) {
        libc::rt_sigaction(signum, nullptr, &state[signum - 1], 8).TRY();
    }
    return {};
}

static Result<void> load(const State &state) {
    for (int signum = 1; signum <= 64; signum++) {
        if (signum == SIGKILL || signum == SIGSTOP) {
            // These can't be changed
            continue;
        }
        libc::rt_sigaction(signum, &state[signum - 1], nullptr, 8).TRY();
    }
    return {};
}

} // namespace signal_handlers
