#include "libc.hpp"
#include "remembrances/alternative_stack.hpp"
#ifdef __x86_64__
#include "remembrances/arch_prctl_options.hpp"
#endif
#include "remembrances/itimers.hpp"
#include "remembrances/pending_signals.hpp"
#include "remembrances/personality.hpp"
#include "remembrances/program_break.hpp"
#include "remembrances/robust_list.hpp"
#include "remembrances/signal_handlers.hpp"
#include "remembrances/thp_options.hpp"
#include "remembrances/tid_address.hpp"
#include "remembrances/umask.hpp"

struct State {
    Result<void> result;
    alternative_stack::State alternative_stack;
#ifdef __x86_64__
    arch_prctl_options::State arch_prctl_options;
#endif
    itimers::State itimers;
    program_break::State program_break;
    pending_signals::State pending_signals;
    personality::State personality;
    robust_futexes::State robust_list;
    signal_handlers::State signal_handlers;
    thp_options::State thp_options;
    tid_address::State tid_address;
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
    pending_signals::save(state.pending_signals).CONTEXT("Failed to save pending signals").TRY();
    personality::save(state.personality).CONTEXT("Failed to save personality").TRY();
    robust_futexes::save(state.robust_list).CONTEXT("Failed to save robust list").TRY();
    signal_handlers::save(state.signal_handlers).CONTEXT("Failed to save signal handlers").TRY();
    thp_options::save(state.thp_options)
        .CONTEXT("Failed to save transparent huge pages options")
        .TRY();
    tid_address::save(state.tid_address).CONTEXT("Failed to save TID address").TRY();
    umask::save(state.umask).CONTEXT("Failed to save umask").TRY();
    return {};
}

FINALIZE_CONTEXTS

extern "C" __attribute__((section(".entry"), naked, flatten, externally_visible)) void _start() {
    pid_t pid = libc::getpid().unwrap();
    state.result = run();
    (void)libc::kill(pid, SIGSTOP);
    // We could use __builtin_unreachable or __builtin_trap here. Ideally we'd use the one that's
    // likely to catch more bugs, but it's uncertain what the distribution actually is.
    // __builtin_unreachable is a pass-through; we're likely to modify memory (including the state)
    // if it is actually executed, thus an error will propagate to the stemcell or be delivered as
    // a errno (perhaps an invalid one). But __builtin_trap is somewhat less dangerous if there's
    // actually a bug and will likely trigger SIGSEGV.
    __builtin_trap();
}
