/*
description: CPU time limit works
slow: true
script: |
    expect(
        run(limits=Metrics(cpu_time=0.5)),
        verdict=Limited(Limit.cpu_time),
        metrics=ApproximateMetrics(
            real_time="0.5 +- 0.05",
            cpu_time="0.5 +- 0.03",
            idleness_time="0 +- 0.05"
        )
    )
*/

int main() {
    for (;;) {
    }
    return 0;
}
