/*
description: TO BE DONE 2
script: |
    pid = prefork()
    expect(pid, verdict=Suspended)
    expect(resume(pid))
*/

#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>

int main(int argc, char **argv) {
    const size_t size = 1LL << 32; // 2 * 65536 * 2 * 4096;

    char *p = mmap(NULL, size, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
    if ((char *)-1 == p) {
        perror("mmap");
        return -1;
    }

    for (int i = 0; i < size; i += 2 * 4096) {
        if (-1 == munmap(p + i, 4096)) {
            puts("Suspend here");
            fflush(stdout);
            return 0;
        }
    }

    fprintf(stderr, "Could not exceed map count");
    return -1;
}
