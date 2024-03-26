#pragma once

#include "result.hpp"
#include <asm/unistd.h>

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
#elif defined(__aarch64__)
long raw_syscall(long number) {
    register long w8 asm("x8") = number;
    register long x0 asm("x0");
    asm volatile("svc 0" : "=r"(x0) : "r"(w8) : "memory");
    return x0;
}
long raw_syscall(long number, long arg0) {
    register long w8 asm("x8") = number;
    register long x0 asm("x0") = arg0;
    asm volatile("svc 0" : "+r"(x0) : "r"(w8) : "memory");
    return x0;
}
long raw_syscall(long number, long arg0, long arg1) {
    register long w8 asm("x8") = number;
    register long x0 asm("x0") = arg0;
    register long x1 asm("x1") = arg1;
    asm volatile("svc 0" : "+r"(x0) : "r"(w8), "r"(x1) : "memory");
    return x0;
}
long raw_syscall(long number, long arg0, long arg1, long arg2) {
    register long w8 asm("x8") = number;
    register long x0 asm("x0") = arg0;
    register long x1 asm("x1") = arg1;
    register long x2 asm("x2") = arg2;
    asm volatile("svc 0" : "+r"(x0) : "r"(w8), "r"(x1), "r"(x2) : "memory");
    return x0;
}
long raw_syscall(long number, long arg0, long arg1, long arg2, long arg3) {
    register long w8 asm("x8") = number;
    register long x0 asm("x0") = arg0;
    register long x1 asm("x1") = arg1;
    register long x2 asm("x2") = arg2;
    register long x3 asm("x3") = arg3;
    asm volatile("svc 0" : "+r"(x0) : "r"(w8), "r"(x1), "r"(x2), "r"(x3) : "memory");
    return x0;
}
long raw_syscall(long number, long arg0, long arg1, long arg2, long arg3, long arg4) {
    register long w8 asm("x8") = number;
    register long x0 asm("x0") = arg0;
    register long x1 asm("x1") = arg1;
    register long x2 asm("x2") = arg2;
    register long x3 asm("x3") = arg3;
    register long x4 asm("x4") = arg4;
    asm volatile("svc 0" : "+r"(x0) : "r"(w8), "r"(x1), "r"(x2), "r"(x3), "r"(x4) : "memory");
    return x0;
}
long raw_syscall(long number, long arg0, long arg1, long arg2, long arg3, long arg4, long arg5) {
    register long w8 asm("x8") = number;
    register long x0 asm("x0") = arg0;
    register long x1 asm("x1") = arg1;
    register long x2 asm("x2") = arg2;
    register long x3 asm("x3") = arg3;
    register long x4 asm("x4") = arg4;
    register long x5 asm("x5") = arg5;
    asm volatile("svc 0"
                 : "+r"(x0)
                 : "r"(w8), "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5)
                 : "memory");
    return x0;
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

// ===== FORWARD DECLARATIONS =====
struct msghdr;
struct cmsghdr;
struct mmsghdr;

// ===== SYSCALLS =====
#include "../target/libc.hpp"

// ===== sys/socket.h =====
struct msghdr {
    void *msg_name;        /* Optional address */
    size_t msg_namelen;    /* Size of address */
    struct iovec *msg_iov; /* Scatter/gather array */
    size_t msg_iovlen;     /* # elements in msg_iov */
    void *msg_control;     /* Ancillary data, see below */
    size_t msg_controllen; /* Ancillary data buffer len */
    int msg_flags;         /* Flags on received message */
};

struct cmsghdr {
    size_t cmsg_len;
    int cmsg_level;
    int cmsg_type;
};

struct ucred {
    pid_t pid;
    uid_t uid;
    gid_t gid;
};

struct mmsghdr {
    struct msghdr msg_hdr;
    unsigned int msg_len;
};

struct sockaddr {
    sa_family_t sa_family;
    char sa_data[14];
};

#define __CMSG_LEN(cmsg) (((cmsg)->cmsg_len + sizeof(long) - 1) & ~(long)(sizeof(long) - 1))
#define __CMSG_NEXT(cmsg) ((unsigned char *)(cmsg) + __CMSG_LEN(cmsg))
#define __MHDR_END(mhdr) ((unsigned char *)(mhdr)->msg_control + (mhdr)->msg_controllen)

#define CMSG_DATA(cmsg) ((unsigned char *)(((struct cmsghdr *)(cmsg)) + 1))
#define CMSG_NXTHDR(mhdr, cmsg)                                                                    \
    ((cmsg)->cmsg_len < sizeof(struct cmsghdr) || __CMSG_LEN(cmsg) + sizeof(struct cmsghdr) >=     \
                                                      __MHDR_END(mhdr) - (unsigned char *)(cmsg)   \
         ? 0                                                                                       \
         : (struct cmsghdr *)__CMSG_NEXT(cmsg))
#define CMSG_FIRSTHDR(mhdr)                                                                        \
    ((size_t)(mhdr)->msg_controllen >= sizeof(struct cmsghdr)                                      \
         ? (struct cmsghdr *)(mhdr)->msg_control                                                   \
         : (struct cmsghdr *)0)

#define CMSG_ALIGN(len) (((len) + sizeof(size_t) - 1) & (size_t) ~(sizeof(size_t) - 1))
#define CMSG_SPACE(len) (CMSG_ALIGN(len) + CMSG_ALIGN(sizeof(struct cmsghdr)))
#define CMSG_LEN(len) (CMSG_ALIGN(sizeof(struct cmsghdr)) + (len))

#define SCM_RIGHTS 0x01
#define SCM_CREDENTIALS 0x02
