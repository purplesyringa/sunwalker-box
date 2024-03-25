/*
description: A delayed signal triggering in parasite does not crash the box
script: |
    import random
    for i in range(60):
        arg = str(random.randint(0, 10 ** 7))
        ctx = f"run {i} arg {arg}"
        pid = prefork(run=Run(argv + [arg]), context=ctx)
        expect(pid, verdict=Suspended)
        expect(resume(pid, context=ctx), verdict=Signaled(14))
*/

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

int main(int argc, char **argv) {
    struct sigevent sev = {
        .sigev_notify = SIGEV_SIGNAL,
        .sigev_signo = SIGALRM,
    };
    timer_t timerid;
    if (timer_create(CLOCK_REALTIME, &sev, &timerid) == -1) {
        perror("timer_create");
        return 1;
    }

    struct itimerspec new_value = {.it_interval = {},
                                   .it_value = {.tv_sec = 0, .tv_nsec = atoi(argv[1])}};
    if (timer_settime(timerid, 0, &new_value, NULL) == -1) {
        perror("timer_settime");
        return 1;
    }

    puts("Suspend here");
    fflush(stdout);

    usleep(1e4);
    return 0;
}
