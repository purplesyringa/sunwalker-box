/*
description: Prefork works after commit and reset
script: |
    commit()
    reset()
    pid = prefork()
    expect(pid, verdict=Suspended)
    expect(resume(pid))
*/

#include <stdio.h>

int main() {
    puts("Suspend here");
    fflush(stdout);
    return 0;
}
