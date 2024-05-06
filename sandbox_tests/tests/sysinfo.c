/*
description: sysinfo should not reveal information
slow: true
script: |
    pv = dict(stdout=PreviousOutput(bias="+- 1"))
    for _ in range(2):
        pv = expect(run(limits=Metrics(memory="200 MB")), **pv)
        run_reset()
*/

#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/sysinfo.h>
#include <unistd.h>

int approx_mem(unsigned long a, unsigned long b) {
    unsigned long diff = a < b ? b - a : a - b;
    return diff < 1024 * 1024;
}

int main() {
    struct sysinfo info;
    if (sysinfo(&info) == -1) {
        perror("sysinfo");
        return 1;
    }

    printf("%ld\n", info.uptime);
    if (info.uptime < 0) {
        fprintf(stderr, "Uptime is negative");
        return 1;
    }

    if (info.loads[0] != 0 || info.loads[1] != 0 || info.loads[2] != 0) {
        fprintf(stderr, "LA is non-zero");
        return 1;
    }

    if (!approx_mem(info.totalram * info.mem_unit, 200 * 1000 * 1000)) {
        fprintf(stderr, "Total RAM is %lu * %u, not 200 MB", info.totalram, info.mem_unit);
        return 1;
    }

    if (!approx_mem(info.freeram * info.mem_unit, 200 * 1000 * 1000)) {
        fprintf(stderr, "Free RAM is %lu * %u, not 200 MB", info.freeram, info.mem_unit);
        return 1;
    }

    if (!approx_mem(info.sharedram * info.mem_unit, 0)) {
        fprintf(stderr, "Shared RAM is %lu * %u, not 0 MB", info.sharedram, info.mem_unit);
        return 1;
    }

    if (info.procs != 1) {
        fprintf(stderr, "Expected 1 running process, got %d\n", info.procs);
        return 1;
    }

    char *p = malloc(10 * 1000 * 1000);
    if (p == NULL) {
        perror("malloc");
        return 1;
    }
    for (int i = 0; i < 10 * 1000 * 1000; i += 4096) {
        p[i] = 0;
    }

    p = mmap(NULL, 20 * 1000 * 1000, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) {
        perror("mmap");
        return 1;
    }
    for (int i = 0; i < 20 * 1000 * 1000; i += 4096) {
        p[i] = 0;
    }

    if (sleep(2) == -1) {
        perror("sleep");
        return 1;
    }

    struct sysinfo info1;
    if (sysinfo(&info1) == -1) {
        perror("sysinfo");
        return 1;
    }

    int diff = info1.uptime - info.uptime;
    // It should be a bit larger than 2 s; due to rounding, this might actually be
    // rounded to 3 s
    if (diff != 2 && diff != 3) {
        fprintf(stderr, "uptime did not change by 2 s or 3 s");
        return 1;
    }

    if (!approx_mem(info1.freeram * info1.mem_unit, 170 * 1000 * 1000)) {
        fprintf(stderr, "Free RAM is %lu * %u, not 170 MB", info1.freeram, info1.mem_unit);
        return 1;
    }

    if (!approx_mem(info1.sharedram * info1.mem_unit, 20 * 1000 * 1000)) {
        fprintf(stderr, "Shared RAM is %lu * %u, not 20 MB", info1.sharedram, info1.mem_unit);
        return 1;
    }

    return 0;
}
