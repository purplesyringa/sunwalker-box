/*
description: Large files cannot be created
quotas:
    space: 10000
script: |
    expect(run())
*/

#include <errno.h>
#include <stdio.h>
#include <string.h>

int main() {
    FILE *f = fopen("/space/test", "w");
    if (f == NULL) {
        perror("Failed to open file");
        return 1;
    }

    char buf[1024];
    memset(buf, 0, sizeof(buf));
    for (int i = 0; i < 1024; i++) {
        if (fwrite(buf, 1, sizeof(buf), f) == 0) {
            if (errno != ENOSPC) {
                perror("Unexpected error while writing");
                return 1;
            }
            return 0;
        }
    }

    fclose(f);

    fprintf(stderr, "Did not fail to write\n");
    return 1;
}
