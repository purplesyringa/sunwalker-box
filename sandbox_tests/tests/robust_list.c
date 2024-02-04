/*
description: Robust list (used for futexes) is not corrupted by prefork
script: |
    pid = prefork()
    expect(pid, verdict=Suspended)
    expect(resume(pid))
*/

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h> /* Definition of SYS_* constants */
#include <unistd.h>

void bail(char *why) {
    fprintf(stderr, "errno %d: %s", errno, why);
    exit(1);
}

#define ensure(x, e)                                                                               \
    if (!(x))                                                                                      \
    bail(e)

#define robust_ptr 0xfee1deadbeef00
#define robust_size 24

int main() {
    long p = 0, x = 0;

    errno = 0;
    syscall(SYS_set_robust_list, robust_ptr, robust_size);
    ensure(!errno, "Could not set robust list");
    syscall(SYS_get_robust_list, 0, &p, &x);
    printf("%lx, %ld\n", p, x);

    puts("Suspend here");
    fflush(stdout); // To ensure suspending

    errno = 0;
    syscall(SYS_get_robust_list, 0, &p, &x);
    printf("%lxs, %ld\n", p, x);
    ensure(!errno, "Could not get robust list");
    ensure(p == robust_ptr, "Robust list head is corrupted");
    ensure(x == robust_size, "Robust list len is corrupted");

    return 0;
}
