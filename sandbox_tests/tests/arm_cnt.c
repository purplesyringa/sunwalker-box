/*
description: arm64 counter-timer registers (cntfrq, cntpct[ss], cntvct[ss]) are unavailable
arch:
- aarch64
expect:
  limit_verdict: Signaled
  exit_code: -4
runs: 5
pass_run_number: true
*/

#pragma GCC target("arch=armv8.6-a")

#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
  int run = atoi(argv[1]);
  long long val;
  if (run == 0) asm volatile("mrs %0, cntfrq_el0" : "=r" (val));
  if (run == 1) asm volatile("mrs %0, cntpctss_el0" : "=r" (val));
  if (run == 2) asm volatile("mrs %0, cntpct_el0" : "=r" (val));
  if (run == 3) asm volatile("mrs %0, cntvctss_el0" : "=r" (val));
  if (run == 4) asm volatile("mrs %0, cntvct_el0" : "=r" (val));
  printf("Counter is %lli\n", val);
  return 0;
}
