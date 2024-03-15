/*
description: Real time limit works
script: |
    expect(
        run(limits=Metrics(real_time=0.2)),
        verdict=Limited(Limit.real_time),
        metrics=ApproximateMetrics(
            real_time="0.2 +- 0.07",
            cpu_time="0 +- 0.01",
            idleness_time="0.2 +- 0.07"
        )
    )
*/

#include <unistd.h>

int main() {
    for (;;) {
        pause();
    }
    return 0;
}
