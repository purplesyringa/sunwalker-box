/*
description: UTS namespace is unshared
script: |
  expect(run())
*/

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main() {
    char name[HOST_NAME_MAX + 1];

    if (getdomainname(name, sizeof(name)) == -1) {
        perror("getdomainname failed");
        return 1;
    }
    if (strcmp(name, "sunwalker") != 0) {
        fprintf(stderr, "Unexpected domain name %s\n", name);
        return 1;
    }

    if (gethostname(name, sizeof(name)) == -1) {
        perror("gethostname failed");
        return 1;
    }
    if (strcmp(name, "box") != 0) {
        fprintf(stderr, "Unexpected hostname %s\n", name);
        return 1;
    }

    return 0;
}
