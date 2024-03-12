/*
description: CPU and real time is accounted correctly in prefork
slow: true
script: |
    pid = prefork()
    expect(pid, verdict=Suspended, metrics=ApproximateMetrics(
        cpu_time="0.1 +- 0.01",
        idleness_time="0.2 +- 0.05",
        real_time="0.3 +- 0.05"
    ))
    expect(resume(pid), metrics=ApproximateMetrics(
        cpu_time="0.20 +- 0.01",
        idleness_time="0.3 +- 0.05",
        real_time="0.50 +- 0.05"
    ))
*/

#include <stdio.h>
#include <time.h>
#include <unistd.h>

int main() {
    while (clock() < CLOCKS_PER_SEC / 10) {
    }
    usleep(200000);
    puts("Suspend here");
    fflush(stdout);
    while (clock() < CLOCKS_PER_SEC / 10) {
    }
    usleep(100000);
    return 0;
}
