/*
description: Peak memory usage is computed correctly in prefork
script: |
    pid = prefork(Run(argv + ["5000000", "1", "10000000"]))
    expect(pid, verdict=Suspended)
    expect(resume(pid), metrics=ApproximateMetrics(memory="10 MB +- 0.5 MB"))

    pid = prefork(Run(argv + ["10000000", "1", "5000000"]))
    expect(pid, verdict=Suspended)
    expect(resume(pid), metrics=ApproximateMetrics(memory="10 MB +- 0.5 MB"))

    pid = prefork(Run(argv + ["5000000", "0", "10000000"]))
    expect(pid, verdict=Suspended)
    expect(resume(pid), metrics=ApproximateMetrics(memory="15 MB +- 0.5 MB"))

    pid = prefork(Run(argv + ["10000000", "0", "5000000"]))
    expect(pid, verdict=Suspended)
    expect(resume(pid), metrics=ApproximateMetrics(memory="15 MB +- 0.5 MB"))
*/

#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>

void commit(size_t size, int unmap) {
    void *p = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) {
        perror("mmap");
        exit(1);
    }
    for (size_t i = 0; i < size; i += 4096) {
        *((char *)p + i) = '\0';
    }
    if (unmap) {
        munmap(p, size);
    }
}

int main(int argc, char **argv) {
    commit(atoi(argv[1]), atoi(argv[2]));
    puts("Suspend here");
    fflush(stdout);
    commit(atoi(argv[3]), 0);
}
