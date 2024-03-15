/*
description: A simple program can be run with limits
script: |
    expect(run(limits=Metrics(
        cpu_time="10 ms",
        idleness_time="50 ms",
        real_time="50 ms",
        memory="0.5 MiB"
    )))
*/

int main() {}
