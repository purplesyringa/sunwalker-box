/*
description: PMCCNTR is unavailable
arch:
- aarch64
expect:
  limit_verdict: Signaled
  exit_code: -4
*/

int main() {
  long long val;
  asm volatile("mrs %0, cntvct_el0" : "=r" (val));
  printf("Counter is %lli\n", val);
  return 0;
}
