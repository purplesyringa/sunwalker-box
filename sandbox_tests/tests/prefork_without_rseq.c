/*
description: Code without rseq survives prefork
script: |
    pid = prefork()
    expect(pid, verdict=Suspended)
    expect(resume(pid), verdict=Exited(123))
*/

// Note that we rely on this code being compiled with musl libc, as glibc sets
// up its own rseq.

#include <stdio.h>

int main() {
    puts("Suspend here");
    fflush(stdout);
    return 123;
}
