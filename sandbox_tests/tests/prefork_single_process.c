/*
description: Processes limit does not break prefork
script: |
    limits = Metrics(processes=1)

    expect(run(input="world", limits=limits), stdout="Hello, world!", stderr="Bye, world!")
    run_reset()

    pid = prefork(limits=limits)
    expect(pid, verdict=Suspended)
    expect(resume(pid, input="world"), stdout="Hello, world!", stderr="Bye, world!")
    expect(resume(pid, input="prefork"), stdout="Hello, prefork!", stderr="Bye, prefork!")
*/

#include <stdio.h>

int main() {
    char name[32];
    fgets(name, sizeof(name), stdin);
    printf("Hello, %s!", name);
    fprintf(stderr, "Bye, %s!", name);
    return 0;
}
