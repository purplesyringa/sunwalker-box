/*
description: Mount binds are readable and not always writable
assets:
  file: ""
preexec:
  - touch /space/readonly /space/readwrite
  - bind -ro @file /space/readonly
  - bind @file /space/readwrite
*/

#include <stdio.h>
#include <stdlib.h>

int main() {
  FILE *f;

  f = fopen("/space/readonly", "rb");
  if (f == NULL) {
    perror("Failed to open /space/readonly for reading");
    return 1;
  }
  fclose(f);

  f = fopen("/space/readonly", "wb");
  if (f != NULL) {
    fprintf(stderr, "Did not fail to open /space/readonly for writing\n");
    return 1;
  }

  f = fopen("/space/readwrite", "wb");
  if (f == NULL) {
    perror("Failed to open /space/readwrite for writing");
    return 1;
  }
  fclose(f);

  return 0;
}
