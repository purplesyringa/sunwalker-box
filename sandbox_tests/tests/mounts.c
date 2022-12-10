/*
description: External mounts are not visible
root: {}
static: true
*/

#include <errno.h>
#include <stdio.h>
#include <string.h>

int main() {
  FILE *f = fopen("/proc/self/mounts", "r");
  if (f == NULL) {
    perror("Failed to read /proc/self/mounts");
    return 1;
  }
  char buf[4096];
  errno = 0;
  while (fgets(buf, sizeof(buf), f) != NULL) {
    if (strncmp(buf, "/dev/", 5) == 0 &&
        strstr(buf, " /space/mounts ") == NULL) {
      fprintf(stderr, "Unexpected mount: %s", buf);
      return 1;
    }
    errno = 0;
  }
  if (errno != 0) {
    perror("Failed to read /proc/self/mounts");
    return 1;
  }
  fclose(f);
  return 0;
}
