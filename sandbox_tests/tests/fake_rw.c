/*
description: |
    Fake-RW files (actually RO, but look like they can be turned +w) do not trigger suspending
script: |
    pid = prefork()
    expect(pid, verdict=Suspended)
    pv = dict(stdout=PreviousOutput())
    for i in range(10):
        pv = expect(resume(pid, context=i), **pv)
*/

#include <errno.h>
#include <fcntl.h>
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

int main() {
    int fd = open("/proc/self/maps", O_RDONLY);
    ensure(sunwalker_check_prefork() == 0, "suspended on open");
    char buf[50];
    ensure(-1 != read(fd, buf, 50), "read");
    ensure(sunwalker_check_prefork() == 0, "suspended on read");
    return -1;
    puts("Suspend here");
    fflush(stdout); // To ensure suspending
    ensure(-1 != read(fd, buf, 50), "read");
    ensure(-1 != write(fd, buf, 50), "write");

    return 0;
}
