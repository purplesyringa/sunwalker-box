#include "../libc.hpp"
#include "../result.hpp"
#include <array>

namespace timers {

struct ParasiteState {
    std::array<int, 64> indices;
    std::array<itimerspec, 64> intervals;
    size_t count;
};

Result<void> save(ParasiteState &state) {
    static itimerspec never;
    for (size_t i = 0; i < state.count; ++i) {
        int timer_id = state.indices[i];
        // Atomically get timer info and disarm it. This is used instead of timer_gettime to avoid
        // the following race condition:
        // 1. We do timer_gettime and see that the timer is supposed to fire soon.
        // 2. The timer expires and adds the signal to the queue.
        // 3. We collect pending signals. The list includes a timer signal.
        // 4. We both deliver the signal and configure the timer to fire soon.
        // 5. As a result, the timer fires twice as opposed to once.
        // Disarming the timer helps avoid the duplication. (Swapping pending signal collection and
        // timer info collection would lead to another race condition, when the timer fires
        // *between* signal and timer collection and is thus swallowed.)
        libc::timer_settime(timer_id, 0, &never, &state.intervals[i])
            .CONTEXT("Could not retrieve timer arming")
            .TRY();
    }
    return {};
}

struct Timer {
    int id;
    int signal;
    void *sigev_value;
    int mechanism;
    pid_t target;
    int clock_id;
};

struct State {
    std::array<Timer, 64> timers;
    std::array<itimerspec, 64> intervals;
    size_t count;
};

// Workaround for glibc bug https://sourceware.org/bugzilla/show_bug.cgi?id=27417
// I hate glibc. Where is this field/define from man sigevent(3type), which exists in musl, but is
// absent from actual glibc headers? Nowhere to be seen. Fucking morons.
#ifndef sigev_notify_thread_id
#define sigev_notify_thread_id _sigev_un._tid
#endif

Result<void> add_timer(const Timer &timer) {
    static int timer_id;
    static sigevent sev;
    sev.sigev_value.sival_ptr = timer.sigev_value;
    sev.sigev_signo = timer.signal;
    sev.sigev_notify = timer.mechanism;
    sev.sigev_notify_thread_id = timer.target;

    // timer_create(3p) in libc says that SIGEV_THREAD creates new thread for signal handler, but
    // proc(5) for `/proc/[pid]/timers` has zero information on what the function for SIGEV_THREAD
    // really is. Linux source code `#ab0a97cffa0b/include/uapi/asm-generic/siginfo.h:312` makes it
    // clear that SIGEV_THREAD is a userspace nonsense and is not handled by kernel in any way.
    // Indeed, if you search for usages of these fields, you will find approximately one usage which
    // is the definition itself.
    // And how am I supposed to know this without summoning a Satan? Not saying this is a bad thing,
    // just... I was not prepared for it.

    libc::timer_create(timer.clock_id, &sev, &timer_id).CONTEXT("Could not create timer").TRY();
    ENSURE(timer.id == timer_id, "Unexpected timer ID");
    return {};
}

Result<void> add_dummy_timer(const int next_timer_id) {
    Timer dummy = {next_timer_id, 0, 0, SIGEV_NONE, 0, CLOCK_REALTIME};
    return add_timer(dummy).CONTEXT("Could not add dummy timer");
}

Result<void> load(const State &state) {
    static int next_timer_id = 0;

    ENSURE(state.count <= 64, "Too many timers!");

    for (int i = 0; i < state.count; ++i) {
        while (next_timer_id < state.timers[i].id) {
            // Create a temporary unused timer to fill the void so that our timer gets the right ID
            add_dummy_timer(next_timer_id).CONTEXT("While dummy creating").TRY();
            next_timer_id += 1;
        }
        add_timer(state.timers[i]).CONTEXT("While timer creating").TRY();
        libc::timer_settime(state.timers[i].id, 0, &state.intervals[i], nullptr)
            .CONTEXT("Could not arm timer")
            .TRY();
        next_timer_id += 1;
    }

    // Remove temporary timers
    next_timer_id = 0;
    for (int i = 0; i < state.count; ++i) {
        while (next_timer_id < state.timers[i].id) {
            libc::timer_delete(next_timer_id).CONTEXT("Could not delete dummy timer").TRY();
            next_timer_id += 1;
        }
        next_timer_id += 1;
    }

    return {};
}

} // namespace timers
