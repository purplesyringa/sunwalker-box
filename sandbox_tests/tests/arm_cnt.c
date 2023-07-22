/*
description: arm64 counter-timer registers (cntpct[ss], cntvct[ss]) are unavailable
arch:
- aarch64
expect:
  limit_verdict: Signaled
  exit_code: -4
runs: 4
pass_run_number: true
*/

#pragma GCC target("arch=armv8.6-a")

#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
  int run = atoi(argv[1]);
  long long val;
  const char* name;
#define REG(reg_name) if(run-- == 0) { name = #reg_name; asm volatile("mrs %0, " #reg_name "_el0" : "=r" (val) ); }
  REG(cntpctss)
  REG(cntpct)
  REG(cntvctss)
  REG(cntvct)
  printf("counter %s is %lli -- should be unavailable or random\n", name, val);
  return 0;
}
