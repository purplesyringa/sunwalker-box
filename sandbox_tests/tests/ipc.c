/*
description: IPC namespace works and is reset
script: |
  pv = {}
  for i in range(2):
    _, _, pv = expect(run(context=i), previous_values=pv, matching_stdout=True)
    run_reset()
*/

#include <fcntl.h>
#include <mqueue.h>
#include <stdio.h>
#include <sys/msg.h>
#include <sys/sem.h>
#include <sys/shm.h>

#define CHECK(code)                                                                                \
    do {                                                                                           \
        int id = code;                                                                             \
        if (id == -1) {                                                                            \
            perror(#code);                                                                         \
            return 1;                                                                              \
        }                                                                                          \
        printf("%d\n", id);                                                                        \
    } while (0);

int main() {
    CHECK(msgget(1, IPC_CREAT | IPC_EXCL | 0666));
    CHECK(msgget(IPC_PRIVATE, 0666));

    CHECK(semget(1, 1, IPC_CREAT | IPC_EXCL | 0666));
    CHECK(semget(IPC_PRIVATE, 1, 0666));

    CHECK(shmget(1, 1, IPC_CREAT | IPC_EXCL | 0666));
    CHECK(shmget(IPC_PRIVATE, 1, 0666));

    CHECK(mq_open("/test", O_RDONLY | O_CREAT | O_EXCL, 0666, NULL));

    return 0;
}
