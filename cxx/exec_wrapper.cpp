#include "libc.hpp"

extern "C" __attribute__((naked, flatten, externally_visible)) void _start() {
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