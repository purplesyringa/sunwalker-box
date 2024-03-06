/*
description: SYS_reboot can be used to ask sunwalker_box if we are suspended or not
script: |
    expect(run())
    pid = prefork(Run(argv + ["use_prefork_test"]))
    expect(pid, verdict=Suspended)
    expect(resume(pid))
*/

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h> /* Definition of SYS_* constants */
#include <unistd.h>

int sunwalker_check_prefork() {
    errno = 0;
    int r = syscall(SYS_reboot, 0xfee1dead, 0x11092001, 0, 0);
    printf("sunwalker returned %d and errno is %d\n", r, errno);
    return -errno;
}

void bail(char *why) {
    fputs(why, stderr);
    exit(1);
}

#define ensure(x, e)                                                                               \
    if (!(x))                                                                                      \
    bail(e)

int main(int argc) {
    if (argc == 1) {
        ensure(sunwalker_check_prefork() == -EINVAL, "Not in 'resumed' state??");
    } else {
        ensure(sunwalker_check_prefork() == 0, "Already resumed?");
        puts("Suspend here");
        fflush(stdout); // To ensure suspending
        ensure(sunwalker_check_prefork() == -EINVAL, "Did not suspend on write??");
    }

    return 0;
}
