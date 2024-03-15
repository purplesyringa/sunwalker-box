/*
description: Cannot unshare any namespace
script: |
    expect(run())
*/

#define _GNU_SOURCE
#include <errno.h>
#include <sched.h>
#include <stdio.h>

#ifndef CLONE_NEWTIME
#define CLONE_NEWTIME 0x80
#endif

int main() {
    int namespaces[] = {CLONE_NEWCGROUP, CLONE_NEWIPC, CLONE_NEWIPC,
                        CLONE_NEWIPC,    CLONE_NEWPID, CLONE_NEWTIME,
                        CLONE_NEWUSER,   CLONE_NEWUTS, 0};
    for (int *p = namespaces; *p; p++) {
        int flag = *p;
        if (unshare(flag) == 0) {
            fprintf(stderr, "unshare(%x) unexpectedly succeeded\n", flag);
            return 1;
        }
    }
    return 0;
}
