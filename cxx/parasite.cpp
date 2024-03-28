#include "libc.hpp"
#include "remembrances/alternative_stack.hpp"
#ifdef __x86_64__
#include "remembrances/arch_prctl_options.hpp"
#endif
#include "remembrances/itimers.hpp"
#include "remembrances/personality.hpp"
#include "remembrances/program_break.hpp"
#include "remembrances/robust_list.hpp"
#include "remembrances/signal_handlers.hpp"
#include "remembrances/thp_options.hpp"
#include "remembrances/tid_address.hpp"
#include "remembrances/timers.hpp"
#include "remembrances/umask.hpp"

struct State {
    Result<void> result;
    alternative_stack::State alternative_stack;
#ifdef __x86_64__
    arch_prctl_options::State arch_prctl_options;
#endif
    itimers::State itimers;
    program_break::State program_break;
    personality::State personality;
    robust_futexes::State robust_list;
    signal_handlers::State signal_handlers;
    thp_options::State thp_options;
    tid_address::State tid_address;
    timers::ParasiteState timer_intervals;
    umask::State umask;
} state __attribute__((externally_visible));

Result<void> run() {
    alternative_stack::save(state.alternative_stack)
        .CONTEXT("Failed to save alternative stack")
        .TRY();
#ifdef __x86_64__
    arch_prctl_options::save(state.arch_prctl_options)
        .CONTEXT("Failed to save arch_prctl options")
        .TRY();
#endif
    itimers::save(state.itimers).CONTEXT("Failed to save interval timers").TRY();
    program_break::save(state.program_break).CONTEXT("Failed to save program break").TRY();
    personality::save(state.personality).CONTEXT("Failed to save personality").TRY();
    robust_futexes::save(state.robust_list).CONTEXT("Failed to save robust list").TRY();
    signal_handlers::save(state.signal_handlers).CONTEXT("Failed to save signal handlers").TRY();
    thp_options::save(state.thp_options)
        .CONTEXT("Failed to save transparent huge pages options")
        .TRY();
    tid_address::save(state.tid_address).CONTEXT("Failed to save TID address").TRY();
    timers::save(state.timer_intervals).CONTEXT("Failed to save timer arming").TRY();
    umask::save(state.umask).CONTEXT("Failed to save umask").TRY();

    // This effectively saves the mm. (vmsplice would be a better solution if pipes supported random
    // reads.) On success, clone will return in both processes and both of them will raise SIGSTOP.
    pid_t pid = libc::clone(CLONE_VM, 0, 0, 0, 0).CONTEXT("Failed to save VM").TRY();
    if (pid == 0) {
        // The child process SID is inherited from the parent. According to fork(2), a new process
        // can't have a PID that matches an existing SID or PGID, so we wouldn't be able to reuse
        // the original process's PID without this.
        (void)libc::setsid();
    }

    return {};
}

FINALIZE_CONTEXTS

extern "C" __attribute__((section(".entry"), naked, flatten, externally_visible)) void _start() {
    state.result = run();
    // Note that this code is supposed to be run in both the original process and the VM process,
    // i.e. we can't cache the PID
    (void)libc::kill(libc::getpid().unwrap(), SIGSTOP);
    // We could use __builtin_unreachable or __builtin_trap here. Ideally we'd use the one that's
    // likely to catch more bugs, but it's uncertain what the distribution actually is.
    // __builtin_unreachable is a pass-through; we're likely to modify memory (including the state)
    // if it is actually executed, thus an error will propagate to the stemcell or be delivered as
    // a errno (perhaps an invalid one). But __builtin_trap is somewhat less dangerous if there's
    // actually a bug and will likely trigger SIGSEGV.
    __builtin_trap();
}
