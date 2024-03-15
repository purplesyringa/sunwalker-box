/*
description: A simple program uses little resources
script:
    expect(run(), metrics=ApproximateMetrics(
        cpu_time="0 +- 0.01",
        idleness_time="0 +- 0.05",
        real_time="0 +- 0.05",
        memory="0 +- 0.5 MiB"
    ))
*/

int main() {}
