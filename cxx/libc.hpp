#pragma once

#include "result.hpp"
#include <sys/syscall.h>

#ifdef __x86_64__
long raw_syscall(long number) {
    asm volatile("syscall" : "+a"(number) : : "rcx", "r11", "memory");
    return number;
}
long raw_syscall(long number, long arg1) {
    asm volatile("syscall" : "+a"(number) : "D"(arg1) : "rcx", "r11", "memory");
    return number;
}
long raw_syscall(long number, long arg1, long arg2) {
    asm volatile("syscall" : "+a"(number) : "D"(arg1), "S"(arg2) : "rcx", "r11", "memory");
    return number;
}
long raw_syscall(long number, long arg1, long arg2, long arg3) {
    asm volatile("syscall"
                 : "+a"(number)
                 : "D"(arg1), "S"(arg2), "d"(arg3)
                 : "rcx", "r11", "memory");
    return number;
}
long raw_syscall(long number, long arg1, long arg2, long arg3, long arg4) {
    register long r10 asm("r10") = arg4;
    asm volatile("syscall"
                 : "+a"(number)
                 : "D"(arg1), "S"(arg2), "d"(arg3), "r"(r10)
                 : "rcx", "r11", "memory");
    return number;
}
long raw_syscall(long number, long arg1, long arg2, long arg3, long arg4, long arg5) {
    register long r10 asm("r10") = arg4;
    register long r8 asm("r8") = arg5;
    asm volatile("syscall"
                 : "+a"(number)
                 : "D"(arg1), "S"(arg2), "d"(arg3), "r"(r10), "r"(r8)
                 : "rcx", "r11", "memory");
    return number;
}
long raw_syscall(long number, long arg1, long arg2, long arg3, long arg4, long arg5, long arg6) {
    register long r10 asm("r10") = arg4;
    register long r8 asm("r8") = arg5;
    register long r9 asm("r9") = arg6;
    asm volatile("syscall"
                 : "+a"(number)
                 : "D"(arg1), "S"(arg2), "d"(arg3), "r"(r10), "r"(r8), "r"(r9)
                 : "rcx", "r11", "memory");
    return number;
}
#else
#error Trying to compile syscall wrappers against unsupported architecture!
#endif

template <typename... Args> Result<long> syscall(Args... args) {
    long result = raw_syscall(args...);
    if (-4096 < result && result < 0) {
        return Error{static_cast<uint16_t>(result)};
    } else {
        return result;
    }
}

namespace libc {
#include "../target/libc.hpp"
}
