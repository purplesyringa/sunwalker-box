/*
description: Prefork works after commit
script: |
    commit()
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
