/*
description: Threads cannot run in parallel
script: |
  expect(run())
*/

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

void *start_routine(void *_arg) {
    unsigned counter = 0;
    for (int i = 0; i < 10000000; i++) {
        counter += (unsigned)i * (i - 1);
    }
    asm("" ::"r"(counter));
    return NULL;
}

long timeit(int n_threads) {
    pthread_t *threads = calloc(n_threads, sizeof(pthread_t));
    if (threads == NULL) {
        fprintf(stderr, "No memory");
        exit(1);
    }

    struct timespec ts_start;
    if (clock_gettime(CLOCK_MONOTONIC, &ts_start) == -1) {
        perror("clock_gettime");
        exit(1);
    }

    for (int i = 0; i < n_threads; i++) {
        if (pthread_create(&threads[i], NULL, start_routine, NULL) == -1) {
            perror("pthread_create");
            exit(1);
        }
    }
    for (int i = 0; i < n_threads; i++) {
        if (pthread_join(threads[i], NULL) == -1) {
            perror("pthread_join");
            exit(1);
        }
    }

    struct timespec ts_end;
    if (clock_gettime(CLOCK_MONOTONIC, &ts_end) == -1) {
        perror("clock_gettime");
        exit(1);
    }

    return (ts_end.tv_sec - ts_start.tv_sec) * 1000000000 + (ts_end.tv_nsec - ts_start.tv_nsec);
}

int main() {
    double factor = (double)(4 * timeit(1)) / timeit(4);
    printf("Parallel run is more efficient than sequential run by a factor of %f\n", factor);
    if (factor > 1.3) {
        return 1;
    }
    return 0;
}
