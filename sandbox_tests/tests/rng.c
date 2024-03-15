/*
description: /dev/random does not deplete entropy pool
script: |
    expect(run())
*/

#include <errno.h>
#include <stdio.h>

int main() {
    FILE *f = fopen("/dev/random", "rb");
    if (f == NULL) {
        perror("Failed to open /dev/random");
        return 1;
    }

    for (int i = 0; i < 100; i++) {
        char buf[1024];
        if (fread(buf, 1, sizeof(buf), f) < sizeof(buf)) {
            fprintf(stderr, "Failed to read %lu bytes from /dev/random\n", sizeof(buf));
            return 1;
        }
    }

    fclose(f);
    return 0;
}
