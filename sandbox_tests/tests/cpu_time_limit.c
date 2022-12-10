/*
description: CPU time limit works
limits:
  cpu_time: 0.2
expect:
  limit_verdict: CPUTimeLimitExceeded
  real_time: 0.2 +- 0.05
  cpu_time: 0.2 +- 0.01
  idleness_time: 0 +- 0.05
*/

int main() {
  for (;;) {
  }
  return 0;
}
