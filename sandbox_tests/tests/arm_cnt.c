/*
description: arm64 counter-timer registers (cntpct[ss], cntvct[ss]) are unavailable
arch:
- aarch64
script: |
  for i in range(4):
    expect(
      run(input=str(i), context=str(i)),
      limit_verdict="Signaled",
      exit_code=-4
    )
    run_reset()
*/

#pragma GCC target("arch=armv8.6-a")

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

unsigned long long load_register(int reg) {
    unsigned long long val;

#define REG(reg_name)                                                                              \
    if (reg-- == 0) {                                                                              \
        asm volatile("mrs %0, " #reg_name "_el0" : "=r"(val));                                     \
    }
    REG(cntpctss)
    REG(cntpct)
    REG(cntvctss)
    REG(cntvct)
#undef REG

    return val;
}

const char *names[] = {"cntpctss", "cntpct", "cntvctss", "cntvct"};

int main(int argc, char **argv) {
    int run = -1;
    scanf("%d", &run);

    unsigned long long before = load_register(run);
    if (usleep(400000) == -1) {
        perror("usleep");
        return 1;
    }
    unsigned long long after = load_register(run);

    if (before < (after - before) / 10) {
        asm volatile("udf #0");
    }

    printf("Counter %s had values %llu and %llu, indicating uptime of more than 40ms\n", names[run],
           before, after);
    return 0;
}
