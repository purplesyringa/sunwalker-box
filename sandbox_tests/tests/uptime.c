/*
description: Uptime should be zero
script: |
  pv = {}
  for _ in range(2):
    _, _, pv = expect(run(), previous_values=pv, matching_stdout="+- 0.1")
    run_reset()
*/

#include <stdio.h>
#include <time.h>
#include <unistd.h>

clockid_t clocks[] = {CLOCK_MONOTONIC, CLOCK_MONOTONIC_RAW, CLOCK_MONOTONIC_COARSE, CLOCK_BOOTTIME,
                      CLOCK_BOOTTIME_ALARM};

#define N_CLOCKS (sizeof(clocks) / sizeof(clocks[0]))

struct timespec saved[N_CLOCKS];

int main() {
    for (int i = 0; i < N_CLOCKS; i++) {
        struct timespec *ts = &saved[i];
        if (clock_gettime(clocks[i], ts) == -1) {
            perror("clock_gettime");
            return 1;
        }
        printf("%ld.%09ld\n", ts->tv_sec, ts->tv_nsec);
        if (ts->tv_sec < 0) {
            fprintf(stderr, "Clock is negative");
            return 1;
        }
    }

    if (usleep(300000) == -1) {
        perror("usleep");
        return 1;
    }

    for (int i = 0; i < N_CLOCKS; i++) {
        struct timespec ts;
        if (clock_gettime(clocks[i], &ts) == -1) {
            perror("clock_gettime");
            return 1;
        }

        long diff_nsec =
            (ts.tv_sec - saved[i].tv_sec) * 1000000000 + (ts.tv_nsec - saved[i].tv_nsec);

        long diff_msec = diff_nsec / 1000000;

        if (!(250 <= diff_msec && diff_msec <= 350)) {
            fprintf(stderr, "Clock #%d was incremented by %ldms, [250; 350] was expected\n", i,
                    diff_msec);
            return 1;
        }
    }

    return 0;
}
