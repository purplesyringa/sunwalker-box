/*
description: A simple program can be run with limits
script:
  expect(
    run(),
    cpu_time_limit=0.01,
    idleness_time_limit=0.05,
    real_time_limit=0.05,
    memory_limit=parse_size("0.5 MiB")
  )
*/

int main() {}
