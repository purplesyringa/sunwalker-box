#include "libc.hpp"
#include <linux/resource.h>
#include <linux/time.h>

__kernel_old_itimerval itimer_prof __attribute__((externally_visible));

Result<void> adjust_itimer() {
    auto &val = itimer_prof.it_value;

    if (0 == val.tv_sec && 0 == val.tv_usec) {
        return {};
    }

    static rusage usage;

    // rusage is preserved across execve, so we have to account for the CPU time we have already
    // spent
    libc::getrusage(RUSAGE_SELF, &usage).TRY();

    auto &user = usage.ru_utime;
    auto &system = usage.ru_stime;

    const int usec_per_sec = 1000000;

    val.tv_sec += user.tv_sec + system.tv_sec;
    val.tv_usec += user.tv_usec + system.tv_usec;
    val.tv_sec += val.tv_usec / usec_per_sec;
    val.tv_usec %= usec_per_sec;

    libc::setitimer(ITIMER_PROF, &itimer_prof, 0).TRY();

    return {};
}

extern "C" __attribute__((naked, flatten, externally_visible)) void _start() {
    (void)adjust_itimer().unwrap();

#ifdef __x86_64__
    register long *stack_pointer asm("rsp");
#elif defined(__aarch64__)
    register long *stack_pointer asm("sp");
#else
#error There is no portable way of getting stack pointer
#endif

    long argc = *stack_pointer;
    char **argv = reinterpret_cast<char **>(stack_pointer + 1);
    char **envp = argv + argc + 1;

    (void)libc::exit(libc::execve(argv[1], argv + 1, envp).unwrap_errno());

    __builtin_trap();
}