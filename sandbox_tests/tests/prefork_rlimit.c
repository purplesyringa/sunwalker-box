/*
description: rlimits are preserved after prefork
script: |
    pid = prefork()
    expect(pid, verdict=Suspended)
    expect(resume(pid))
*/

#define _GNU_SOURCE
#include <stdio.h>
#include <sys/resource.h>

int main() {
    for (int i = 0; i < 16; i++) {
        if (i == RLIMIT_AS || i == RLIMIT_DATA || i == RLIMIT_CORE || i == RLIMIT_NICE ||
            i == RLIMIT_RTPRIO) {
            continue;
        }
        struct rlimit rlim;
        rlim.rlim_cur = 10000 + i;
        rlim.rlim_max = 20000 + i;
        if (setrlimit(i, &rlim) == -1) {
            fprintf(stderr, "Failed to set rlimit %d\n", i);
            perror("setrlimit");
            return 1;
        }
    }

    puts("Suspend here");
    fflush(stdout);

    for (int i = 0; i < 16; i++) {
        if (i == RLIMIT_AS || i == RLIMIT_DATA || i == RLIMIT_CORE || i == RLIMIT_NICE ||
            i == RLIMIT_RTPRIO) {
            continue;
        }
        struct rlimit rlim;
        if (getrlimit(i, &rlim) == -1) {
            perror("getrlimit");
            return 1;
        }
        if (rlim.rlim_cur != 10000 + i || rlim.rlim_max != 20000 + i) {
            fprintf(stderr, "rlimit %d was not preserved (read out cur=%llu, max=%llu)\n", i,
                    rlim.rlim_cur, rlim.rlim_max);
            return 1;
        }
    }

    return 0;
}
