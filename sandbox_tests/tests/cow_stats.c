/*
description: CoW memory is not counted twice
script: |
  expect(run(), memory="14 MiB +- 0.5 MiB")
*/

#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

int main() {
  char *p = mmap(NULL, 10 * 1024 * 1024, PROT_READ | PROT_WRITE,
                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (p == MAP_FAILED) {
    perror("mmap");
    exit(1);
  }

  for (size_t i = 4 * 1024 * 1024; i < 10 * 1024 * 1024; i += 4096) {
    p[i] = '\0';
  }

  pid_t child = fork();
  if (child == -1) {
    perror("fork");
    return 1;
  }

  // Rewrite just 4 MiB; this is divisible by 2 MiB, which is huge page size on x86-64
  if (child == 0) {
    for (size_t i = 0; i < 4 * 1024 * 1024; i += 4096) {
      p[i] = '\1';
    }
  } else {
    for (size_t i = 0; i < 4 * 1024 * 1024; i += 4096) {
      p[i] = '\2';
    }
    int wstatus;
    if (wait(&wstatus) != child) {
      perror("wait");
      return 1;
    }
  }
}
