/*
description: Cannot allocate more memory than allowed
limits:
  memory: 200 MB
expect:
  limit_verdict: MemoryLimitExceeded
*/

#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>

void *alloc_committed(size_t size) {
  void *p = mmap(NULL, size, PROT_READ | PROT_WRITE,
                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (p == MAP_FAILED) {
    return NULL;
  }
  for (size_t i = 0; i < size; i += 4096) {
    *((char *)p + i) = '\0';
  }
  return p;
}

int main() {
  if (alloc_committed(180 * 1000 * 1000) == NULL) {
    fprintf(stderr, "Failed to allocate 180 MB\n");
    return 1;
  }
  if (alloc_committed(20 * 1000 * 1000) != NULL) {
    fprintf(stderr, "Did not fail to allocate 20 more MB\n");
    return 1;
  }
  fprintf(stderr, "Program was not killed despite trying to allocate more "
                  "memory than allowed");
  return 1;
}
