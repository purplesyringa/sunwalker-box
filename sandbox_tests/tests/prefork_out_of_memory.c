/*
description: Reaching ML in prefork does not crash the box
script: |
    import random
    for _ in range(10):
        arg = str(random.randint(10, 20))
        preforked = prefork(
            run=Run(argv + [arg]),
            limits=Metrics(memory="172 KiB"),
        )
        if preforked.verdict == Limited(Limit.memory) or type(preforked.verdict) is Signaled:
            pass
        else:
            expect(preforked, verdict=Suspended)
            expect(resume(preforked))
*/

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/resource.h>

int main(int argc, char **argv) {
    int n_pages = atoi(argv[1]);
    char *p =
        mmap(NULL, n_pages * 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    for (int i = 0; i < n_pages * 4096; i += 4096) {
        p[i] = 1;
    }

    puts("Suspend here");
    fflush(stdout);
    return 0;
}
