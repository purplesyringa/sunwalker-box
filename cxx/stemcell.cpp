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
#include <numeric>

struct State {
    Result<void> result;
    uintptr_t end_of_original_master_mapping;
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
    uint32_t allowed_to_munmap_self;
} state __attribute__((externally_visible));

struct ControlMessage {};

struct ControlMessageFds {
    std::array<int, 3> stdio;
    int cwd;
};

extern char start_of_text;
extern char end_of_bss;
size_t stemcell_size;

uintptr_t task_size;
int memfd;

Result<uintptr_t> guess_task_size() {
    // We need to know TASK_SIZE so that we know how to munmap everything after the last mapping we
    // want to retain. The kernel does not let us learn TASK_SIZE directly, even via auxv. This is
    // certainly a ridiculous situation to be in, but we can learn TASK_SIZE anyway with a
    // workaround. munmap fails with EINVAL if we attempt to unmap a page past TASK_SIZE. We know
    // that nothing is mapped past end_of_original_master_mapping at the moment in user portion of
    // virtual memory ([vsyscall] is in kernel memory past TASK_SIZE), so we can just binary-search
    // the address.

    // FIXME: This assumes PAGE_SIZE is 4096
    uintptr_t left = state.end_of_original_master_mapping >> 12;
    // The highest byte of a pointer will be unset, see https://lwn.net/Articles/834289/
    uintptr_t right = uintptr_t{1} << (56 - 12);
    while (right - left > 1) {
        uintptr_t mid = std::midpoint(left, right);
        bool is_einval = libc::munmap(mid << 12, 4096)
                             .swallow(EINVAL, 1)
                             .CONTEXT("Unexpected failure in munmap")
                             .TRY();
        if (is_einval) {
            right = mid;
        } else {
            left = mid;
        }
    }

    return right << 12;
}

Result<void> run() {
    stemcell_size = &end_of_bss - &start_of_text;
    task_size = guess_task_size().CONTEXT("Failed to guess TASK_SIZE").TRY();

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
                 task_size - reinterpret_cast<uintptr_t>(&end_of_bss))
        .CONTEXT("Failed to munmap memory suffix")
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
    umask::load(state.umask).CONTEXT("Failed to load umask").TRY();

    // Block all signals. (Note that this does not block *synchronous* signals forcefully delivered
    // by the kernel, like SIGSEGV on #GP, SIGBUS on #PF, or SIGILL on #UD.) Signals might cause
    // problems if delivered by interval timers or POSIX timers while we're in stemcell.
    static uint64_t sigset = -1;
    libc::rt_sigprocmask(SIG_SETMASK, reinterpret_cast<sigset_t *>(&sigset), nullptr,
                         sizeof(sigset))
        .CONTEXT("Failed to disable interval timers signals")
        .TRY();

    // Relocate ourselves from anonymous memory to file-backed memory. This is supposed to reduce
    // restoration of stemcell after it is unmapped to a single mmap syscall.
    memfd = libc::memfd_create("stemcell", 0).CONTEXT("Failed to create memfd").TRY();
    size_t n_written =
        libc::write(memfd, &start_of_text, stemcell_size).CONTEXT("Failed to write to memfd").TRY();
    ENSURE(n_written == stemcell_size, "Unexpected length written to memfd");
    libc::mmap(reinterpret_cast<unsigned long>(&start_of_text), stemcell_size,
               PROT_READ | PROT_WRITE | PROT_EXEC, MAP_FIXED | MAP_SHARED, memfd, 0)
        .CONTEXT("Failed to remap self from memfd")
        .TRY();

    return {};
}

Result<void> init_child(const ControlMessageFds &fds) {
    // Stop us from being able to touch the parent process in any way save for mm modification
    libc::setresuid(1000, 1000, 1000).CONTEXT("Failed to drop privileges").TRY();

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

    libc::close(memfd).CONTEXT("Failed to close memfd").TRY();

    // At this point, all fds save for 0-2 are controlled by remembrances and have been made
    // available in the stemcell via sunwalker_box transferred_fds facility. This guarantees that
    // they don't intersect the fds used by the original process (again, save for 0-2) that we shall
    // restore later

    libc::close(state.controlling_fd).CONTEXT("Failed to close controlling fd").TRY();

    // clone(CLONE_VM) resets alternative stack, so it has to be restored after fork
    alternative_stack::load(state.alternative_stack)
        .CONTEXT("Failed to load alternative stack")
        .TRY();

    // File descriptors have to be restored after fork, as dup2 doesn't clone the underlying file
    // descriptor but uses the same one, and thus updates to file offset and other information would
    // be shared between runs
    file_descriptors::load(state.file_descriptors).CONTEXT("Failed to load file descriptors").TRY();

    // We do not, strictly speaking, need to handle memory maps in the fork child. However, it has
    // to happen on each run, and the VM are shared between the master copy and the forked process
    // so this place is as good as any
    memory_maps::load(state.memory_maps, task_size, reinterpret_cast<uintptr_t>(&start_of_text))
        .CONTEXT("Failed to load memory maps")
        .TRY();

    // Memory options are stored in the mm structure and thus shared with the master process, so
    // they have to be restored every time
    mm_options::load(state.mm_options).CONTEXT("Failed to load memory map options").TRY();

    // Pending signals have to be injected after fork
    pending_signals::load(state.pending_signals).CONTEXT("Failed to load pending signals").TRY();

    // Robust lists are per-thread, therefore restore them after fork
    robust_futexes::load(state.robust_list).CONTEXT("Failed to load robust list").TRY();

    // rseq has to be restored after memory so that the kernel can read the structures. We also
    // ensure rseq_cs is reset to 0 while suspending, so stemcell code won't be interpreted as a
    // critical section and aborted.
    rsequence::load(state.rseq).CONTEXT("Failed to load rseq").TRY();

    while (!state.allowed_to_munmap_self) {
        libc::futex(&state.allowed_to_munmap_self, FUTEX_WAIT, 0, nullptr, nullptr, 0)
            .CONTEXT("Failed to wait on futex")
            .TRY();
    }

    // Loading timers has to happen at each run to preserve expiration times so that time doesn't
    // flow between suspend and resume. The less time passes between timer restoration and execution
    // of user code, the better. Therefore, restore them only after waiting on the futex.
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

    libc::munmap(reinterpret_cast<unsigned long>(&start_of_text), stemcell_size)
        .CONTEXT("Failed to munmap stemcell")
        .TRY();
    __builtin_trap();

    // By now, two things aren't replicated:
    // - signal mask
    // - CPU state
}

pid_t master_pid;

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
        .flags = CLONE_CHILD_CLEARTID | CLONE_PARENT | CLONE_VM,
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
            (void)libc::kill(master_pid, SIGKILL);
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

        // In the parent process, the syscall that immediately follows clone3 must be mmap. The
        // manager will put us into syscall-enter-stop, which enables it to mmap stuff later into
        // the stemcell mm even after any user code has run in this mm.
        (void)libc::mmap(reinterpret_cast<unsigned long>(&start_of_text), stemcell_size,
                         PROT_READ | PROT_WRITE | PROT_EXEC, MAP_FIXED | MAP_SHARED, memfd, 0);

        // Make sure not to cause any errors between clone3 and recvmsg -- these would be caught by
        // running, which has no idea what to do about them
        for (int i = 0; i < 3; i++) {
            (void)libc::close(fds.stdio[i]);
        }
        (void)libc::close(fds.cwd);
    }
}

extern "C" __attribute__((naked, flatten, externally_visible)) void _start() {
    master_pid = libc::getpid().unwrap();
    if (!libc::ptrace(PTRACE_TRACEME, 0, 0, 0).is_ok()) {
        (void)libc::kill(master_pid, SIGKILL);
        __builtin_unreachable();
    }
    (void)libc::kill(master_pid, SIGSTOP);
    state.result = run();
    (void)libc::kill(master_pid, SIGSTOP);
    state.result = loop();
    (void)libc::kill(master_pid, SIGSTOP);
    __builtin_trap();
}

FINALIZE_CONTEXTS
