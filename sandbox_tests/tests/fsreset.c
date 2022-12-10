/*
description: Filesystem is totally restored on reset
root: {}
runs: 3
static: true
expect:
  matching_stdout: true
*/

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

char path[1024];
char *path_end = path;

int handle_entry(int dirfd, struct dirent *ent);

int walk(int dirfd) {
  DIR *dir = fdopendir(dirfd);
  if (dir == NULL) {
    fprintf(stderr, "Failed to open %s: ", path);
    perror("fdopendir");
    return -1;
  }

  struct dirent *ent;
  errno = 0;
  while ((ent = readdir(dir))) {
    if (handle_entry(dirfd, ent) == -1) {
      closedir(dir);
      return -1;
    }
    errno = 0;
  }

  if (errno != 0) {
    closedir(dir);
    fprintf(stderr, "Failed to read %s: ", path);
    perror("readdir");
    return -1;
  }

  if (closedir(dir) == -1) {
    fprintf(stderr, "Failed to close %s: ", path);
    perror("closedir");
    return -1;
  }

  return 0;
}

int handle_entry(int dirfd, struct dirent *ent) {
  if (ent->d_name[0] == '.' &&
      (ent->d_name[1] == '\0' ||
       (ent->d_name[1] == '.' && ent->d_name[2] == '\0'))) {
    return 0;
  }

  char *prev_path_end = path_end;
  *path_end++ = '/';
  path_end = stpcpy(path_end, ent->d_name);

  int ret = 0;

  printf("%s\n", path);

  if (ent->d_type == DT_DIR) {
    int fd = openat(dirfd, ent->d_name, O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW);
    if (fd == -1) {
      if (errno == EACCES) {
        printf("[EACCES]\n");
      } else {
        fprintf(stderr, "Failed to open %s: ", path);
        perror("openat");
        ret = -1;
      }
    } else {
      ret = walk(fd);
    }
  }

  path_end = prev_path_end;
  *path_end = '\0';

  return ret;
}

void dumpfs() {
  int dirfd = open("/", O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW);
  if (dirfd == -1) {
    perror("Failed to open /: open");
    exit(1);
  }
  if (walk(dirfd) == -1) {
    exit(1);
  }
}

int main() {
  dumpfs();

  const char *paths[] = {"/space/newfile",    "/space/.tmp/test1", "/tmp/test2",
                         "/space/.shm/test3", "/dev/shm/test4",    NULL};

  for (const char **path = paths; *path; path++) {
    if (access(*path, F_OK) != -1) {
      fprintf(stderr, "%s exists unexpectedly", *path);
      return 1;
    }
    FILE *f = fopen(*path, "wb");
    if (f == NULL) {
      fprintf(stderr, "Failed to create %s: ", *path);
      perror("fopen");
      return 1;
    }
    fclose(f);
  }

  return 0;
}
