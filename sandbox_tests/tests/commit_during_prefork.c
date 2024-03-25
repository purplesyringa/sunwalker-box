/*
description: Commit works with an alive prefork process
script: |
    pid = prefork()
    expect(pid, verdict=Suspended)
    commit()
    expect(resume(pid))
*/

#include <fcntl.h>
#include <stdio.h>

int main() {
    if (open("/proc/self/exe", O_RDONLY) == -1) {
        perror("open");
        return 1;
    }
    puts("Suspend here");
    fflush(stdout);
    return 0;
}
