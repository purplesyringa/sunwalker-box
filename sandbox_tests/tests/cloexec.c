/*
description: File descriptors do not leak
script: |
    expect(run())
*/

#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

int main() {
    DIR *dir = opendir("/proc/self/fd");
    if (dir == NULL) {
        perror("Failed to open /proc/self/fd");
        return 1;
    }

    struct dirent *ent;
    errno = 0;
    while ((ent = readdir(dir))) {
        int fd = atoi(ent->d_name);
        if (fd >= 3 && fd != dirfd(dir)) {
            fprintf(stderr, "fd %d is unexpectedly open\n", fd);
            return 1;
        }
        errno = 0;
    }

    if (errno != 0) {
        perror("Failed to readdir");
        return 1;
    }

    closedir(dir);
    return 0;
}
