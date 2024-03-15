/*
description: CoW memory is not counted twice
script: |
    expect(run(), metrics=ApproximateMetrics(memory="14 MiB +- 0.5 MiB"))
*/

#include <errno.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <unistd.h>

int main() {
    char *p =
        mmap(NULL, 10 * 1024 * 1024, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) {
        perror("mmap");
        return 1;
    }

    for (size_t i = 4 * 1024 * 1024; i < 10 * 1024 * 1024; i += 4096) {
        p[i] = '\0';
    }

    int sv[2];
    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) == -1) {
        perror("socketpair");
        return 1;
    }

    pid_t child = fork();
    if (child == -1) {
        perror("fork");
        return 1;
    }

    // Rewrite just 4 MiB; this is divisible by 2 MiB, which is huge page size on x86-64
    int index = child == 0;
    for (size_t i = 0; i < 4 * 1024 * 1024; i += 4096) {
        p[i] = 1 + index;
    }

    if (write(sv[index], ".", 1) == -1) {
        perror("write");
        return 1;
    }

    char c;
    if (read(sv[index], &c, 1) != 1) {
        perror("read");
        return 1;
    }

    return 0;
}
