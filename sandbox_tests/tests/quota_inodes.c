/*
description: Many files cannot be created
quotas:
  inodes: 100
*/

#include <errno.h>
#include <stdio.h>
#include <string.h>

int main() {
  for (int i = 0; i < 200; i++) {
    char name[50];
    sprintf(name, "/space/test%d", i);

    FILE *f = fopen(name, "w");
    if (f == NULL) {
      if (errno != ENOSPC) {
        perror("Unexpected error while opening file");
        return 1;
      }
      return 0;
    }

    fclose(f);
  }

  fprintf(stderr, "Did not fail to create files\n");
  return 1;
}
