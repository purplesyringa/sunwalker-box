/*
description: Real time is restricted correctly in prefork
slow: true
script: |
    results = {
        "limit_verdict": "RealTimeLimitExceeded",
        "real_time": "0.5 +- 0.05",
    }

    pid = prefork(limits=Metrics(real_time=.5))
    expect(pid, verdict=Suspended)

    expect(
        resume(pid, input="0"),
        verdict=Limited(Limit.real_time),
        metrics=ApproximateMetrics(
            cpu_time="0.2 +- 0.03",
            idleness_time="0.3 +- 0.05",
            real_time="0.5 +- 0.05",
        )
    )

    expect(
        resume(pid, input="1"),
        verdict=Limited(Limit.real_time),
        metrics=ApproximateMetrics(
            cpu_time="0.4 +- 0.03",
            idleness_time="0.1 +- 0.05",
            real_time="0.5 +- 0.05",
        )
    )
*/

#include <stdio.h>
#include <time.h>
#include <unistd.h>

int main() {
    while (clock() < CLOCKS_PER_SEC / 10 * 2) {
    }
    usleep(100000);
    puts("Suspend here");
    fflush(stdout);
    int v;
    scanf("%d", &v);
    if (v == 0) {
        usleep(300000);
    } else {
        while (clock() < CLOCKS_PER_SEC / 10 * 3) {
        }
    }
    return 0;
}
