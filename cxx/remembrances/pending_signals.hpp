#include "../libc.hpp"

namespace pending_signals {

static constexpr size_t MAX_PENDING_SIGNALS = 1024;

struct State {
    size_t count_per_thread;
    size_t count_per_process;
    std::array<siginfo_t, MAX_PENDING_SIGNALS> pending_per_thread;
    std::array<siginfo_t, MAX_PENDING_SIGNALS> pending_per_process;
};

Result<void> load(const State &state) {
    pid_t pid = libc::getpid().unwrap();
    for (size_t i = 0; i < state.count_per_thread; i++) {
        const siginfo_t &info = state.pending_per_thread[i];
        libc::rt_tgsigqueueinfo(pid, pid, info.si_signo, const_cast<siginfo_t *>(&info))
            .CONTEXT("Failed to inject per-thread signal")
            .TRY();
    }
    for (size_t i = 0; i < state.count_per_process; i++) {
        const siginfo_t &info = state.pending_per_process[i];
        libc::rt_sigqueueinfo(pid, info.si_signo, const_cast<siginfo_t *>(&info))
            .CONTEXT("Failed to inject per-process signal")
            .TRY();
    }
    return {};
}

} // namespace pending_signals
