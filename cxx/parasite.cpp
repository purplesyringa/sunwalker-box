#include "libc.hpp"
#include "remembrances/alternative_stack.hpp"
#include "remembrances/arch_prctl_options.hpp"
#include "remembrances/itimers.hpp"
#include "remembrances/pending_signals.hpp"
#include "remembrances/personality.hpp"
#include "remembrances/program_break.hpp"
#include "remembrances/signal_handlers.hpp"
#include "remembrances/signal_mask.hpp"
#include "remembrances/thp_options.hpp"
#include "remembrances/tid_address.hpp"
#include "remembrances/umask.hpp"

struct State {
    Result<void> result;
    alternative_stack::State alternative_stack;
    arch_prctl_options::State arch_prctl_options;
    itimers::State itimers;
    program_break::State program_break;
    pending_signals::State pending_signals;
    personality::State personality;
    signal_handlers::State signal_handlers;
    signal_mask::State signal_mask;
    thp_options::State thp_options;
    tid_address::State tid_address;
    umask::State umask;
} state;

static Result<void> run() {
    alternative_stack::save(state.alternative_stack)
        .CONTEXT("Failed to save alternative stack")
        .TRY();
    arch_prctl_options::save(state.arch_prctl_options)
        .CONTEXT("Failed to save arch_prctl options")
        .TRY();
    itimers::save(state.itimers).CONTEXT("Failed to save interval timers").TRY();
    program_break::save(state.program_break).CONTEXT("Failed to save program break").TRY();
    pending_signals::save(state.pending_signals).CONTEXT("Failed to save pending signals").TRY();
    personality::save(state.personality).CONTEXT("Failed to save personality").TRY();
    signal_handlers::save(state.signal_handlers).CONTEXT("Failed to save signal handlers").TRY();
    signal_mask::save(state.signal_mask).CONTEXT("Failed to save signal mask").TRY();
    thp_options::save(state.thp_options)
        .CONTEXT("Failed to save transparent huge pages options")
        .TRY();
    tid_address::save(state.tid_address).CONTEXT("Failed to save TID address").TRY();
    umask::save(state.umask).CONTEXT("Failed to save umask").TRY();
    return {};
}

FINALIZE_CONTEXTS

extern "C" __attribute__((section(".entry"))) __attribute__((naked)) void _start() {
    state.result = run();
    (void)libc::kill(0, SIGSTOP);
    __builtin_unreachable();
}
