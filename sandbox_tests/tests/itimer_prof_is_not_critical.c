/*
description: CPU time limit works without itimer
script:
  expect(
    run(cpu_time_limit=0.2),
    limit_verdict="CPUTimeLimitExceeded",
    real_time="0.23 +- 0.03",
    cpu_time="0.23 +- 0.03",
    idleness_time="0 +- 0.05",
  )
  # cpu_time: around 50ms are wasted due to polling
*/

#include <stdio.h>
#include <string.h>
#include <sys/time.h>

int main() {
  struct itimerval timer;
  memset(&timer, 0, sizeof(timer));
  if (setitimer(ITIMER_PROF, &timer, NULL) == -1) {
    perror("setitimer");
    return 1;
  }
  for (;;) {
  }
  return 0;
}
