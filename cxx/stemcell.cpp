#include "libc.hpp"
#include "remembrances/alternative_stack.hpp"
#ifdef __x86_64__
#include "remembrances/arch_prctl_options.hpp"
#endif
#include "remembrances/file_descriptors.hpp"
#include "remembrances/itimers.hpp"
#include "remembrances/memory_maps.hpp"
#include "remembrances/mm_options.hpp"
#include "remembrances/pending_signals.hpp"
#include "remembrances/personality.hpp"
#include "remembrances/robust_list.hpp"
#include "remembrances/rseq.hpp"
#include "remembrances/signal_handlers.hpp"
#include "remembrances/thp_options.hpp"
#include "remembrances/tid_address.hpp"
#include "remembrances/timers.hpp"
#include "remembrances/umask.hpp"
#include <linux/prctl.h>
#include <linux/ptrace.h>

struct State {
    Result<void> result;
    uintptr_t end_of_memory_space;
    alternative_stack::State alternative_stack;
#ifdef __x86_64__
    arch_prctl_options::State arch_prctl_options;
#endif
    file_descriptors::State file_descriptors;
    itimers::State itimers;
    memory_maps::State memory_maps;
    mm_options::State mm_options;
    pending_signals::State pending_signals;
    personality::State personality;
    robust_futexes::State robust_list;
    rsequence::State rseq;
    signal_handlers::State signal_handlers;
    thp_options::State thp_options;
    tid_address::State tid_address;
    timers::State timers;
    umask::State umask;
    int controlling_fd;
} state __attribute__((externally_visible));

struct ControlMessage {};

struct ControlMessageFds {
    std::array<int, 3> stdio;
    int cwd;
};

extern char start_of_text;
extern char end_of_bss;

Result<void> run() {
    // Parent sets us to 1001/1000/1001, but that results in just 1001/1000/1000 in child because
    // that's how execve works. Fix this so that our rUID/sUID aren't 1000 and we can't be killed.
    // This is inherently racy, but everyone else is supposed to be stopped at this moment.
    libc::setresuid(1001, 1000, 1001).CONTEXT("Failed to drop privileges").TRY();

    libc::prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0).CONTEXT("Failed to set no_new_privs").TRY();

    // Unmap everything the kernel has mapped for us, including stack, because we aren't using it
    // (provided the stemcell was compiled correctly)
    libc::munmap(0, reinterpret_cast<size_t>(&start_of_text))
        .CONTEXT("Failed to munmap memory prefix")
        .TRY();
    // We can't hard-code any particular upper bound because it is not only arch-dependent, but
    // kernel-configuration-dependent too, e.g. on x86-64 if 5-level page tables are available
    libc::munmap(reinterpret_cast<unsigned long>(&end_of_bss),
                 state.end_of_memory_space - reinterpret_cast<uintptr_t>(&end_of_bss))
        .CONTEXT("Failed to munmap memory suffix")
        .TRY();

    // We aren't going to trigger any signals in the stemcell, so this is safe to perform
    alternative_stack::load(state.alternative_stack)
        .CONTEXT("Failed to load alternative stack")
        .TRY();

#ifdef __x86_64__
    // We don't rely on limited CPU features or use TLS, so this is safe to perform
    arch_prctl_options::load(state.arch_prctl_options)
        .CONTEXT("Failed to load arch_prctl options")
        .TRY();
#endif

    // Transparent huge pages should be enabled before mapping memory
    thp_options::load(state.thp_options)
        .CONTEXT("Failed to load transparent huge pages options")
        .TRY();
    // Memory maps can be restored almost completely, except for shared memory and removing the
    // stemcell pages
    memory_maps::load_before_fork(state.memory_maps).CONTEXT("Failed to load memory maps").TRY();
    // Memory options can be restored after memory has been mapped
    mm_options::load(state.mm_options).CONTEXT("Failed to load memory map options").TRY();
    // Some personality options are unlikely to cause issues, others are iffy (e.g.
    // ADDR_COMPAT_LAYOUT, ADDR_COMPAT_LAYOUT, ADDR_COMPAT_LAYOUT). We support all of them,
    // best-effort, and hope the most dangerous ones aren't really used. Luckily, stemcell is
    // untrusted, so this can cause odd behavior at worst
    personality::load(state.personality).CONTEXT("Failed to load personality").TRY();
    // rseq is inherited after fork. We also ensure rseq_cs is reset to 0 while suspending, so
    // stemcell code won't be interpreted as a critical section and aborted.
    rsequence::load(state.rseq).CONTEXT("Failed to load rseq").TRY();
    // We aren't going to intentionally cause any signals to be delivered, except SIGSTOP.
    // Unintentional ones, like SIGSEGV, are unlikely and shall be considered bugs by themselves.
    // The only potential issue is SIGCONT, which we'll trigger inadvertently when starting user
    // code. FIXME: can we do anything about this?
    signal_handlers::load(state.signal_handlers).CONTEXT("Failed to load signal handlers").TRY();
    umask::load(state.umask).CONTEXT("Failed to load umask").TRY();

    // Block all signals. (Note that this does not block *synchronous* signals forcefully delivered
    // by the kernel, like SIGSEGV on #GP, SIGBUS on #PF, or SIGILL on #UD.) Signals might cause
    // problems if delivered by interval timers or POSIX timers while we're in stemcell.
    static uint64_t sigset = -1;
    libc::rt_sigprocmask(SIG_SETMASK, reinterpret_cast<sigset_t *>(&sigset), nullptr,
                         sizeof(sigset))
        .CONTEXT("Failed to disable interval timers signals")
        .TRY();

    return {};
}

Result<void> init_child(const ControlMessageFds &fds) {
    // Stop us from being able to touch the parent process in any way
    libc::setresuid(1000, 1000, 1000).CONTEXT("Failed to drop privileges").TRY();

    // Shared pages have to be unshared between instances of clones, so do this after fork
    memory_maps::load_after_fork(state.memory_maps)
        .CONTEXT("Failed to load shared memory maps")
        .TRY();

    // Remap stdio
    for (int i = 0; i < 3; i++) {
        int fd = fds.stdio[i];
        libc::dup3(fd, i, 0).CONTEXT("Failed to dup2 standard stream").TRY();
        libc::close(fd).CONTEXT("Failed to close standard stream").TRY();
    }

    // Working directory has to be restored after fork, as it might have been changed to a different
    // mount during reset, even though the path stays the same. We pass cwd to each instantiation of
    // the resumed process as opposed to reopening it manually for simplicity
    libc::fchdir(fds.cwd).CONTEXT("Failed to set cwd").TRY();
    libc::close(fds.cwd).CONTEXT("Failed to close cwd").TRY();

    // At this point, all fds save for 0-2 are controlled by remembrances and have been made
    // available in the stemcell via sunwalker_box transferred_fds facility. This guarantees that
    // they don't intersect the fds used by the original process (again, save for 0-2) that we shall
    // restore later

    libc::close(state.controlling_fd).CONTEXT("Failed to close controlling fd").TRY();

    // Robust lists are per-thread therefore restore them after fork
    robust_futexes::load(state.robust_list).CONTEXT("Failed to load robust list").TRY();

    // File descriptors have to be restored after fork, as dup2 doesn't clone the underlying file
    // descriptor but uses the same one, and thus updates to file offset and other information would
    // be shared between runs
    file_descriptors::load(state.file_descriptors).CONTEXT("Failed to load file descriptors").TRY();

    // Pending signals have to be injected after fork
    pending_signals::load(state.pending_signals).CONTEXT("Failed to load pending signals").TRY();

    // Loading timers has to happen at each run to preserve expiration times so that time doesn't
    // flow between suspend and resume. Also, timers aren't even inherited.
    itimers::load(state.itimers).CONTEXT("Failed to load interval timers").TRY();
    timers::load(state.timers).CONTEXT("Failed to load POSIX timers").TRY();

    // Unmap self, finally. We have to somehow specify we're ready for that and the SIGSEGV is not
    // just a bug, so put a magic value to a register beforehand. We can't put it to memory (say,
    // state) because, duh, we're going to unmap it, and sending a signal would require a syscall,
    // and at that point it'd be more efficient to do munmap from manager, which is pretty
    // inefficient in comparison to this workaround
#ifdef __x86_64__
    asm volatile("mov $0x5afec0def1e1d, %rsp");
#elif defined(__aarch64__)
    asm volatile("mov sp, %0" : : "r"(0x5afec0def1e1d));
#else
#error Trying to compile stemcell against unsupported architecture!
#endif

    libc::munmap(reinterpret_cast<unsigned long>(&start_of_text), &end_of_bss - &start_of_text)
        .CONTEXT("Failed to munmap stemcell")
        .TRY();
    __builtin_trap();

    // By now, two things aren't replicated:
    // - signal mask
    // - CPU state
}

Result<void> loop() {
    static ControlMessage control_message;

    static iovec iov{
        .iov_base = &control_message,
        .iov_len = sizeof(control_message),
    };

    alignas(cmsghdr) static char cmsg[CMSG_SPACE(sizeof(ControlMessageFds))];

    static msghdr msg{
        .msg_iov = &iov,
        .msg_iovlen = 1,
        .msg_control = cmsg,
    };

    static clone_args cl_args{
        .flags = CLONE_CHILD_CLEARTID | CLONE_PARENT,
    };
    cl_args.child_tid = state.tid_address;

    for (;;) {
        msg.msg_controllen = sizeof(cmsg);

        // Avoid raising SIGSTOP on failure to recvmsg: an error or EOF likely indicates the runner
        // does not care about this process at the moment and will notice the SIGSTOP during the
        // next waitid, where such a singal on a "new" process will be interpreted as a fork
        // notification. Any other signal will correctly crash the sandbox if it isn't ignored. To
        // avoid accidentally sending an ignored signal, always use SIGKILL for simplicity. This can
        // be reworked later if greater flexibility is needed.
        ssize_t n_received = 0;
        auto result = libc::recvmsg(state.controlling_fd, &msg, 0);
        if (result.is_ok()) {
            n_received = std::move(result).unwrap();
        }
        if (n_received == 0) {
            (void)libc::kill(libc::getpid().unwrap(), SIGKILL);
            __builtin_unreachable();
        }
        ENSURE(n_received == sizeof(control_message), "Unexpected size of control message");

        cmsghdr *cmsgp = CMSG_FIRSTHDR(&msg);
        ENSURE(cmsgp != nullptr, "No ancillary data in control message");
        ENSURE(cmsgp->cmsg_len == CMSG_LEN(sizeof(ControlMessageFds)),
               "Invalid size of ancillary data in control message");
        ENSURE(cmsgp->cmsg_level == SOL_SOCKET, "Unexpected cmsg level");
        ENSURE(cmsgp->cmsg_type == SCM_RIGHTS, "Unexpected cmsg type");

        static ControlMessageFds fds;
        __builtin_memcpy(&fds, CMSG_DATA(cmsgp), sizeof(fds));

        pid_t child_pid =
            libc::clone3(&cl_args, sizeof(cl_args)).CONTEXT("Failed to clone self").TRY();

        if (child_pid == 0) {
            state.result = init_child(fds);
            (void)libc::kill(libc::getpid().unwrap(), SIGSTOP);
            __builtin_trap();
        }

        // Make sure not to cause any errors between clone3 and recvmsg -- these would be caught by
        // running, which has no idea what to do about them
        for (int i = 0; i < 3; i++) {
            (void)libc::close(fds.stdio[i]);
        }
        (void)libc::close(fds.cwd);
    }
}

extern "C" __attribute__((naked, flatten, externally_visible)) void _start() {
    pid_t pid = libc::getpid().unwrap();
    if (!libc::ptrace(PTRACE_TRACEME, 0, 0, 0).is_ok()) {
        (void)libc::kill(pid, SIGKILL);
        __builtin_unreachable();
    }
    (void)libc::kill(pid, SIGSTOP);
    state.result = run();
    (void)libc::kill(pid, SIGSTOP);
    state.result = loop();
    (void)libc::kill(pid, SIGSTOP);
    __builtin_trap();
}

FINALIZE_CONTEXTS
