/*
description: Suspend inside a critical section aborts it
script: |
    pid = prefork()
    expect(pid, verdict=Suspended)
    expect(resume(pid), verdict=Exited(123))
*/

#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <unistd.h>

// Copied from UAPI
struct rseq {
    uint32_t cpu_id_start;
    uint32_t cpu_id;
    uint64_t rseq_cs;
    uint32_t flags;
    uint32_t node_id;
    uint32_t mm_cid;
} __attribute__((__aligned__(32)));

struct rseq_cs {
    uint32_t version;
    uint32_t flags;
    uint64_t start_ip;
    uint64_t post_commit_offset;
    uint64_t abort_ip;
} __attribute__((__aligned__(32)));

int main() {
    struct rseq rseq;
    rseq.rseq_cs = 0;
    rseq.flags = 0;

    uint32_t signature = ((uint32_t *)&&cs_abort)[-1];
    uint32_t signature2 = ((uint32_t *)&&cs2_abort)[-1];
    if (signature != signature2) {
        fprintf(stderr,
                "Signatures don't match (%x vs %x). This is a bug in the test "
                "someone should fix.\n",
                signature, signature2);
        return 1;
    }

    if (syscall(SYS_rseq, &rseq, sizeof(rseq), 0, signature) == -1) {
        perror("rseq");
        return 1;
    }

    struct rseq_cs rseq_cs;
    rseq_cs.version = 0;
    rseq_cs.flags = 0;
    rseq_cs.start_ip = (uint64_t) && cs_start;
    rseq_cs.post_commit_offset = (uint64_t) && cs_end - (uint64_t) && cs_start;
    rseq_cs.abort_ip = (uint64_t) && cs_abort;

    *(volatile uint64_t *)&rseq.rseq_cs = (uint64_t)&rseq_cs;

cs_start:
    // Yay, critical section! This should have been written in assembly. Oh well.

    // Trigger a suspending syscall, e.g. write(1, NULL, 0)
#ifdef __x86_64__
    long syscall_no = 1;
    asm goto("syscall" : "+a"(syscall_no) : "D"(1), "S"(0), "d"(0) : "rcx", "r11" : cs_abort);
#elif defined(__aarch64__)
    register long w8 asm("x8") = 1;
    register long x0 asm("x0") = 1;
    register long x1 asm("x1") = 0;
    register long x2 asm("x2") = 0;
    asm goto("svc 0" : "+r"(x0) : "r"(w8), "r"(x1), "r"(x2) : : cs_abort);
#else
#error Unsupported architecture
#endif

cs_end:
    // We are not supposed to have completed CS
    // Use a round-about way to exit without triggering dead code elimination so
    // that the nop sequence is retained and can be used as a signature
    syscall(SYS_exit, 1);

    asm volatile("nop\n\tnop\n\tnop\n\tnop");
    __builtin_unreachable();
cs_abort:
    // Yay for women's rights

    // Make sure the CS is reset
    if (rseq.rseq_cs != 0) {
        return 2;
    }

    // Make sure the rseq object is still registered
    rseq_cs.start_ip = (uint64_t) && cs2_start;
    rseq_cs.post_commit_offset = (uint64_t) && cs2_end - (uint64_t) && cs2_start;
    rseq_cs.abort_ip = (uint64_t) && cs2_abort;

    *(volatile uint64_t *)&rseq.rseq_cs = (uint64_t)&rseq_cs;

cs2_start:
    // This is supposed to be preempted
    for (;;) {
        asm goto("" : : : : cs2_end, cs2_abort);
    }

cs2_end:
    // We are not supposed to have completed CS
    // Use a round-about way to exit without triggering dead code elimination so
    // that the nop sequence is retained and can be used as a signature
    syscall(SYS_exit, 3);

    asm volatile("nop\n\tnop\n\tnop\n\tnop");
    __builtin_unreachable();
cs2_abort:
    return 123;
}
