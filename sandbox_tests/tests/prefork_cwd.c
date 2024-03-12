/*
description: CWD is preserved upon prefork
script: |
    pid = prefork()
    expect(pid, verdict=Suspended)
    reset()
    touch("/tmp/meow")
    expect(resume(pid))
*/

#include <stdio.h>
#include <unistd.h>

int main() {
    if (chdir("/tmp") == -1) {
        perror("chdir");
        return 1;
    }

    puts("Suspend here");
    fflush(stdout);

    if (access("meow", F_OK) == -1) {
        perror("access");
        return 1;
    }

    return 0;
}
