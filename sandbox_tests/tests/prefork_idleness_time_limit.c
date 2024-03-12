/*
description: Idleness time is restricted correctly in prefork
slow: true
script: |
    pid = prefork(limits=Metrics(idleness_time=.5))
    expect(pid, verdict=Suspended)
    expect(
        resume(pid),
        verdict=Limited(Limit.idleness_time),
        metrics=ApproximateMetrics(
            real_time="0.5 +- 0.07",
            cpu_time="0 +- 0.03",
            idleness_time="0.5 +- 0.05",
        )
    )
*/

#include <stdio.h>
#include <time.h>
#include <unistd.h>

int main() {
    usleep(300000);
    puts("Suspend here");
    fflush(stdout);
    usleep(300000);
    return 0;
}
