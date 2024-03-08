/*
description: CPU time limit works
script: |
  expect(
    run(cpu_time_limit=0.5),
    limit_verdict="CPUTimeLimitExceeded",
    real_time="0.5 +- 0.05",
    cpu_time="0.5 +- 0.03",
    idleness_time="0 +- 0.05"
  )
*/

int main() {
  for (;;) {
  }
  return 0;
}
