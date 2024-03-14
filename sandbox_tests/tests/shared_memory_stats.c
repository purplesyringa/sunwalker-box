/*
description: Peak shared memory usage is computed correctly
script: |
  expect(run(), memory="10 MB +- 0.5 MB")
*/

#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>

void *alloc_committed(size_t size) {
    void *p = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) {
        perror("mmap");
        exit(1);
    }
    for (size_t i = 0; i < size; i += 4096) {
        *((char *)p + i) = '\0';
    }
    return p;
}

int main() { alloc_committed(10000000); }
