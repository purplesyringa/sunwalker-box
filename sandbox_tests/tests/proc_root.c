/*
description: External root is inaccessible via procfs
static: true
root: {}
*/

#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

int main() {
  DIR *dir = opendir("/proc");
  if (dir == NULL) {
    perror("Failed to open /proc");
    return 1;
  }

  struct dirent *ent;
  errno = 0;
  while ((ent = readdir(dir))) {
    char path[300];
    sprintf(path, "/proc/%s/root/etc/passwd", ent->d_name);
    FILE *f = fopen(path, "rb");
    if (f != NULL) {
      fprintf(stderr, "Did not fail to open %s\n", path);
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
