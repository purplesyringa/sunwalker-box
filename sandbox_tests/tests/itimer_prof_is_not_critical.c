/*
description: CPU time limit works without itimer
limits:
  cpu_time: 0.2
expect:
  limit_verdict: CPUTimeLimitExceeded
  real_time: 0.23 +- 0.03
  cpu_time: 0.23 +- 0.03  # around 50ms are wasted due to polling
  idleness_time: 0 +- 0.05
*/

#include <stdio.h>
#include <sys/time.h>

int main() {
  struct itimerval timer;
  if (setitimer(ITIMER_PROF, &timer, NULL) == -1) {
    perror("setitimer");
    return 1;
  }
  for (;;) {
  }
  return 0;
}
