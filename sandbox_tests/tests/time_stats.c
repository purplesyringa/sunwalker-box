/*
description: CPU and real time is accounted correctly
expect:
    cpu_time: 0.1 +- 0.01
    idleness_time: 0.2 +- 0.05
    real_time: 0.3 +- 0.05
*/

#include <time.h>
#include <unistd.h>

int main() {
  while (clock() < CLOCKS_PER_SEC / 10) {
  }
  usleep(200000);
  return 0;
}
