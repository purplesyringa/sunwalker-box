#include "libc.hpp"
#include <sys/resource.h>
#include <sys/time.h>

itimerval itimer_prof __attribute__((externally_visible));

Result<void> adjust_itimer() {
    timeval &val = itimer_prof.it_value;

    if (0 == val.tv_sec && 0 == val.tv_usec) {
        return {};
    }

    static struct rusage usage;

    // rusage is preserved across execve, so we have to account for the CPU time we have already
    // spent
    libc::getrusage(RUSAGE_SELF, &usage).TRY();

    timeval &user = usage.ru_utime;
    timeval &system = usage.ru_stime;

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
    long *argv = stack_pointer + 1;
    long *envp = argv + argc + 1;

    (void)libc::exit(libc::execve(argv[1], argv + 1, envp).unwrap_errno());

    __builtin_trap();
}