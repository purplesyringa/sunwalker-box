/*
description: Many small files cannot be created
quotas:
  space: 10000
script: |
  expect(run())
*/

#include <errno.h>
#include <stdio.h>
#include <string.h>

int main() {
  char buf[1024];
  memset(buf, 0, sizeof(buf));

  for (int i = 0; i < 10; i++) {
    char name[50];
    sprintf(name, "/space/test%d", i);

    FILE *f = fopen(name, "w");
    if (f == NULL) {
      perror("Failed to open file");
      return 1;
    }

    if (fwrite(buf, 1, sizeof(buf), f) < sizeof(buf)) {
      if (errno != ENOSPC) {
        perror("Unexpected error while writing");
        return 1;
      }
      return 0;
    }

    if (fclose(f) < 0) {
      if (errno != ENOSPC) {
        perror("Unexpected error while closing");
        return 1;
      }
      return 0;
    }
  }

  fprintf(stderr, "Did not fail to write files\n");
  return 1;
}
