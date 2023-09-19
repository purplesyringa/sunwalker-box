/*
description: rdtsc passes just like clock()
arch:
- x86_64
*/

#include <stdio.h>
#include <sys/prctl.h>
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

  // Check that PR_SET_TSC does not work
  _mm_lfence();
  unsigned long long start = __rdtsc();
  _mm_lfence();
  busy_loop(100000);
  _mm_lfence();
  unsigned long long mid = __rdtsc();
  _mm_lfence();
  if (prctl(PR_SET_TSC, PR_TSC_ENABLE) == -1) {
    perror("prctl");
    return 1;
  }
  _mm_lfence();
  unsigned long long end = __rdtsc();
  _mm_lfence();
  fprintf(stderr, "%llu %llu %llu\n", start, mid, end);
  if (end < mid || end - mid > (mid - start) * 2) {
    fprintf(stderr, "Time jumped too much\n");
    return 1;
  }

  return 0;
}
