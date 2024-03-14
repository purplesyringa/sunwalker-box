/*
description: Real time limit works
script: |
  expect(
    run(real_time_limit=0.2),
    limit_verdict="RealTimeLimitExceeded",
    real_time="0.2 +- 0.07",
    cpu_time="0 +- 0.01",
    idleness_time="0.2 +- 0.07"
  )
*/

#include <unistd.h>

int main() {
    for (;;) {
        pause();
    }
    return 0;
}
