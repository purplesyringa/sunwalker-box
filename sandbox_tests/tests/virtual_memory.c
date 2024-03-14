/*
description: Virtual memory (uncommitted) is not subject to memory limit
script: |
  expect(run(memory_limit=parse_size("20 MB")), memory="10 MB +- 1 MB")
*/

#include <stdio.h>
#include <sys/mman.h>

int main() {
    // "Allocate" (reserve) a somewhat huge chunk
    char *p = (char *)mmap(NULL, 40 * 1024 * 1024, PROT_READ | PROT_WRITE,
                           MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
    if (p == NULL) {
        fprintf(stderr, "Failed to allocate never-committed memory above commit limit\n");
        return 1;
    }

    // And commit a bit of that chunk
    for (int i = 0; i < 10 * 1024 * 1024; i += 4096) {
        p[i] = 0;
    }

    return 0;
}
