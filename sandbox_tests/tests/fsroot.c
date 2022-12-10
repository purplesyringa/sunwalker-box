/*
description: Filesystem is collectly recreated
root:
  rootfile: Root file
  rootdir:
    nestedfile: Nested file
    nestedsymlink1: -> /absolute/path
    nestedsymlink2: -> relative/path
  rootsymlink1: -> /absolute/path
  rootsymlink2: -> relative/path
static: true
expect:
  stdout: |
    /tmp/
    /proc/
    /dev/
    /dev/shm/
    /dev/ptmx
    /dev/pts/
    /dev/pts/ptmx
    /dev/mqueue/
    /dev/fd -> /proc/self/fd
    /dev/tty
    /dev/stderr -> /proc/self/fd/2
    /dev/stdout -> /proc/self/fd/1
    /dev/stdin -> /proc/self/fd/0
    /dev/random
    /dev/urandom
    /dev/zero
    /dev/full
    /dev/null
    /space/
    /space/stderr.txt
    /space/stdout.txt
    /space/fsroot
    /space/.tmp/
    /space/.shm/
    /rootsymlink1 -> /absolute/path
    /rootdir/
    /rootdir/nestedsymlink1 -> /absolute/path
    /rootdir/nestedsymlink2 -> relative/path
    /rootdir/nestedfile
    /rootsymlink2 -> relative/path
    /rootfile
  unordered_stdout: true
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

  if (ent->d_type == DT_DIR) {
    printf("%s/\n", path);
    if (strcmp(path, "/proc") != 0) {
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
  } else if (ent->d_type == DT_LNK) {
    char target[256];
    int target_len = readlinkat(dirfd, ent->d_name, target, sizeof(target));
    if (target_len == -1) {
      fprintf(stderr, "Failed to readlink %s: ", path);
      perror("readlinkat");
      ret = -1;
    } else {
      printf("%s -> %.*s\n", path, target_len, target);
    }
  } else {
    printf("%s\n", path);
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

  return 0;
}
