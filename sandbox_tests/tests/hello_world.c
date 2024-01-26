/*
description: A simple program works as intended
script: |
    expect(run(input="world"), stdout="Hello, world!", stderr="Bye, world!")
    run_reset()

    pid = prefork()
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
