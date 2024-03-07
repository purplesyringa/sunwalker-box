/*
description: closed memfds are freed on memory pressure
script: |
  expect(run(memory_limit=parse_size("1.2 MiB")))
*/

#define _GNU_SOURCE
#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>

int main() {
  int fd1 = memfd_create("test1", 0);
  if (fd1 == -1) {
    perror("memfd_create");
    return 1;
  }

  int fd2 = memfd_create("test2", 0);
  if (fd2 == -1) {
    perror("memfd_create");
    return 1;
  }

  char buf[1024];

  for (int i = 0; i < 1024; i++) {
    if (write(fd1, buf, 1024) != 1024) {
      perror("write");
      return 1;
    }
  }

  close(fd1);

  for (int i = 0; i < 1024; i++) {
    if (write(fd2, buf, 1024) != 1024) {
      perror("write");
      return 1;
    }
  }

  return 0;
}
