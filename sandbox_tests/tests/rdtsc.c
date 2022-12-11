/*
description: rdtsc passes just like clock()
*/

#include <stdio.h>
#include <time.h>
#include <x86intrin.h>

void busy_loop(int n) {
  for (int i = 0; i < n; i++) {
    asm volatile("");
  }
}

#define TEST(fn)                                                               \
  {                                                                            \
    _mm_lfence();                                                              \
    unsigned long long start = fn;                                             \
    _mm_lfence();                                                              \
    busy_loop(50000000);                                                       \
    _mm_lfence();                                                              \
    unsigned long long mid = fn;                                               \
    _mm_lfence();                                                              \
    busy_loop(100000000);                                                      \
    _mm_lfence();                                                              \
    unsigned long long end = fn;                                               \
    _mm_lfence();                                                              \
                                                                               \
    fprintf(stderr, "%llu %llu %llu\n", start, mid, end);                      \
                                                                               \
    double factor = (double)(end - mid) / (2 * (mid - start));                 \
    if (!(0.9 <= factor && factor <= 1.1)) {                                   \
      fprintf(                                                                 \
          stderr,                                                              \
          "TSC does not seem to be proportional to time spent (factor %f)\n",  \
          factor);                                                             \
      return 1;                                                                \
    }                                                                          \
  }

int main() {
  TEST(__rdtsc());

  unsigned aux;
  TEST(__rdtscp(&aux));

  return 0;
}
