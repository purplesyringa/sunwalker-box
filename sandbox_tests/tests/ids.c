/*
description: UIDs and GIDs are always 1000
script: |
    expect(run())

    pid = prefork()
    expect(pid, verdict=Suspended)
    expect(resume(pid))
*/

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void compare(int id, const char *name) {
    if (id != 1000) {
        printf("Unexpected %s %d\n", name, id);
        exit(1);
    }
}

void check() {
    int ruid, euid, suid;
    getresuid(&ruid, &euid, &suid);
    compare(ruid, "real UID");
    compare(euid, "effective UID");
    compare(suid, "saved UID");

    int rgid, egid, sgid;
    getresgid(&rgid, &egid, &sgid);
    compare(rgid, "real GID");
    compare(egid, "effective GID");
    compare(sgid, "saved GID");
}

int main() {
    check();
    puts("Suspend here");
    fflush(stdout);
    check();
}
