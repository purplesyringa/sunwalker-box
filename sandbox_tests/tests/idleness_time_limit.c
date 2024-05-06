/*
description: Idleness time limit works
slow: true
script: |
    expect(
        run(limits=Metrics(idleness_time=0.2)),
        verdict=Limited(Limit.idleness_time),
        metrics=ApproximateMetrics(
            real_time="0.3 +- 0.07",
            cpu_time="0.1 +- 0.01",
            idleness_time="0.2 +- 0.07"
        )
    )
*/

#include <time.h>
#include <unistd.h>

int main() {
    while (clock() < CLOCKS_PER_SEC / 10) {
    }
    for (;;) {
        pause();
    }
    return 0;
}
