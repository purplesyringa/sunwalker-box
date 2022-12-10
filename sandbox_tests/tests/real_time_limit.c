/*
description: Real time limit works
limits:
  real_time: 0.2
expect:
  limit_verdict: RealTimeLimitExceeded
  real_time: 0.2 +- 0.07
  cpu_time: 0 +- 0.01
  idleness_time: 0.2 +- 0.07
*/

#include <unistd.h>

int main() {
  for (;;) {
    pause();
  }
  return 0;
}
