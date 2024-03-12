/*
description: TO BE DONE
script: |
    pid = prefork()
    pid = expect(pid, verdict=Suspended)
    expect(resume(pid))
*/

#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>

int main(int argc, char **argv) {
    char *p = mmap(NULL, 128LL * 1024 * 1024 * 1024, PROT_READ,
                   MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
    if (p == MAP_FAILED) {
        perror("mmap");
        return -1;
    }

    puts("Suspend here");
    fflush(stdout);
    return 0;
}
