#include "libc.hpp"
#include "remembrances/alternative_stack.hpp"
#include "remembrances/arch_prctl_options.hpp"
#include "remembrances/file_descriptors.hpp"
#include "remembrances/itimers.hpp"
#include "remembrances/memory_maps.hpp"
#include "remembrances/mm_options.hpp"
#include "remembrances/personality.hpp"
#include "remembrances/signal_handlers.hpp"
#include "remembrances/thp_options.hpp"
#include "remembrances/tid_address.hpp"
#include "remembrances/umask.hpp"

struct State {
    Result<void> result;
    alternative_stack::State alternative_stack;
    arch_prctl_options::State arch_prctl_options;
    file_descriptors::State file_descriptors;
    itimers::State itimers;
    memory_maps::State memory_maps;
    mm_options::State mm_options;
    personality::State personality;
    signal_handlers::State signal_handlers;
    thp_options::State thp_options;
    tid_address::State tid_address;
    umask::State umask;
} state;

extern char start_of_text;

static Result<void> run() {
    // Unmap everything the kernel has mapped for us, including stack, because we aren't using it
    // (provided the stemcell was compiled correctly)
    libc::munmap(0, reinterpret_cast<size_t>(&start_of_text))
        .CONTEXT("Failed to munmap memory prefix")
        .TRY();
    uintptr_t end = reinterpret_cast<uintptr_t>(&start_of_text) + 0x1000000;
    // FIXME: This is only valid for x86-64
    libc::munmap(end, 0x7ffffffff000 - end).CONTEXT("Failed to munmap memory suffix").TRY();

    // We aren't going to trigger any signals in the stemcell, so this is safe to perform
    alternative_stack::load(state.alternative_stack)
        .CONTEXT("Failed to load alternative stack")
        .TRY();
    // We don't rely on limited CPU features or use TLS, so this is safe to perform
    arch_prctl_options::load(state.arch_prctl_options)
        .CONTEXT("Failed to load arch_prctl options")
        .TRY();

    // Block signals delivered by interval times. These are going to cause problems if sent while in
    // stemcell, so avoid them entirely
    // Use static to avoid stack
    static uint64_t sigset = SIGALRM | SIGVTALRM | SIGPROF;
    libc::rt_sigprocmask(SIG_SETMASK, &sigset, nullptr, sizeof(sigset))
        .CONTEXT("Failed to disable interval timers signals")
        .TRY();
    itimers::load(state.itimers).CONTEXT("Failed to load interval timers").TRY();

    // Transparent huge pages should be enabled before mapping memory
    thp_options::load(state.thp_options)
        .CONTEXT("Failed to load transparent huge pages options")
        .TRY();
    // Memory maps can be restored almost completely, except for removing the stemcell pages
    memory_maps::load(state.memory_maps).CONTEXT("Failed to load memory maps").TRY();
    // Memory options can be restored after memory has been mapped
    mm_options::load(state.mm_options).CONTEXT("Failed to load memory map options").TRY();
    // Some personality options are unlikely to cause issues, others are iffy (e.g.
    // ADDR_COMPAT_LAYOUT, ADDR_COMPAT_LAYOUT, ADDR_COMPAT_LAYOUT). We support all of them,
    // best-effort, and hope the most dangerous ones aren't really used. Luckily, stemcell is
    // untrusted, so this can cause odd behavior at worst
    personality::load(state.personality).CONTEXT("Failed to load personality").TRY();
    // We aren't going to intentionally cause any signals to be delivered, except SIGSTOP.
    // Unintentional ones, like SIGSEGV, are unlikely and shall be considered bugs by themselves.
    // The only potential issue is SIGCONT, which we'll trigger inadvertently when starting user
    // code. FIXME: can we do anything about this?
    signal_handlers::load(state.signal_handlers).CONTEXT("Failed to load signal handlers").TRY();
    // This is fine to load after memory has been mapped. The thread is not going to die until after
    // stemcell is unmapped unless the stemcell itself dies, so there is no issue if clear_child_tid
    // points at the stemcell
    tid_address::load(state.tid_address).CONTEXT("Failed to load TID address").TRY();
    umask::load(state.umask).CONTEXT("Failed to load umask").TRY();

    // By now, five things aren't replicated:
    // - fds
    // - pid
    // - signal mask
    // - unmap stemcell
    // - cwd

    // File descriptors have to be restored after fork, as dup2 doesn't clone the underlying file
    // descriptor but uses the same one, and thus updates to file offset and other information would
    // be shared between runs
    // file_descriptors::load(state.file_descriptors).CONTEXT("Failed to load file
    //     descriptors").TRY();

    // Working directory has to be restored after fork, as it might have been changed to a different
    // mount during reset, even though the path stays the same

    return {};
}

FINALIZE_CONTEXTS

extern "C" __attribute__((naked)) void _start() {
    state.result = run();
    (void)libc::kill(0, SIGSTOP);

    // // Avoid stack use with static
    // static clone_args cl_args;
    // cl_args.flags = ...;
    // cl_args.pidfd = nullptr;
    // cl_args.child_tid = nullptr;
    // cl_args.parent_tid = nullptr;
    // // Avoid subscribing to signals so that there are no monotonic counters
    // cl_args.exit_signal = 0;
    // // rsp is set in the manager
    // cl_args.stack = nullptr;
    // cl_args.stack_size = 0;
    // // TLS has already been restored
    // cl_args.tls = nullptr;
    // cl_args.set_tid = ...;
    // cl_args.set_tid_size = ...;
    // cl_args.cgroup = ...;
    // libc::clone3(&cl_args, sizeof(cl_args));

    __builtin_unreachable();
}
