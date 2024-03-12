/*
description: CPU time is restricted correctly in prefork
slow: true
script: |
    pid = prefork(limits=Metrics(cpu_time=.5))
    expect(pid, verdict=Suspended)
    expect(
        resume(pid),
        verdict=Limited(Limit.cpu_time),
        metrics=ApproximateMetrics(
            real_time="0.5 +- 0.05",
            cpu_time="0.5 +- 0.03",
            idleness_time="0 +- 0.05",
        )
    )
*/

#include <stdio.h>
#include <time.h>
#include <unistd.h>

int main() {
    while (clock() < CLOCKS_PER_SEC / 10 * 3) {
    }
    puts("Suspend here");
    fflush(stdout);
    while (clock() < CLOCKS_PER_SEC / 10 * 3) {
    }
    return 0;
}
