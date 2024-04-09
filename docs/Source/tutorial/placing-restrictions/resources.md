System resources
================

Many programs nowadays expect that memory allocation is an infallible operation and may behave in an unexpected way when system is out of memory, for example hanging or crashing. OOM means that there is no free RAM and swap space left, that is there's nowhere to commit new pages, and the kernel may kill some processes which use a lot of RAM to free up some space.

You can prevent OOMing the entire system by restricting available commited RAM for sandboxed process by setting `memory` limit in `limits`. Note that virtual space remains unlimited as it is a per-process thing and reaching the kernel limit won't make your system unusable.

Consider the following program that leaks memory in chunks of 16 mebibytes.

```c
// gcc oom.c -o oom
#include <stddef.h>
#include <sys/mman.h>

void *commit_something(size_t size) {
    void *p = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) {
        return NULL;
    }
    for (size_t i = 0; i < size; i += 4096) {
        *((char *)p + i) = '\0';  // Touches every page
    }
    return p;
}

int main() 
{
    while (NULL != commit_something(16 << 20)) {
        continue;
    }

    return 1;
}
```

Running it on my machine resulted in three minutes of hung system. (Hanging was caused by `systemd-journald` which noticed memory shortage and started flushing its caches which delayed the OOM killer)

```shell
$ gcc oom.c -o oom
$ \time ./oom
Command terminated by signal 9
1.00user 6.18system 3:02.00elapsed 3%CPU (0avgtext+0avgdata 13678528maxresident)k
244904inputs+0outputs (96major+2186131minor)pagefaults 0swaps
```

However, running this program under sunwalker-box is safe:

```json
{
    "command": "run",
    "payload": {
        "argv": ["/space/oom"],
        "limits": {
            "memory": 1000000000,  // 1 GB
        }
    }
}
{
    "status": "Success",
    "data": {
        "verdict": { "kind": "LimitExceeded", "limit": "memory" },
        "metrics": { "cpu_time": 0.128677, "real_time": 0.13174758, "idleness_time": 0.00307058, "memory": 999997440 }
    }
}
```

The program exceeded its memory limit and got killed, which is shown in the verdict. Peak memory usage may be slightly less than the provided limit because memory limit is rounded down to the page size.

OOM can also be reached with fork bomb, but it's _also_ dangerous because the amount of processes that can coexist in the system is very limited: `/proc/sys/kernel/threads-max` is usually about 60k.

sunwalker-box can restrict maximal number of processes that can exist simultaneously within the box, thus preventing fork bombs from bombing the system.

```json
{
    "command": "run",
    "payload": {
        "argv": ["/bin/sh", "-c", "fork(){ fork|fork& }; fork"],
        "limits": { "processes": 100 }
    }
}
{
    "status": "Success",
    "data": {
        "verdict": { "kind": "Exited", "exit_code": 0 },
        "metrics": { "cpu_time": 0.004053, "real_time": 0.005723092, "idleness_time": 0.001670092, "memory": 1024000 }
    }
}
```

Note that failure in creating a child is handled by the program itself. This means that there is no "Processes limit exceeded" verdict, and the process may silently wait for a chance of creating new processes. Therefore, setting a time limit is also necessary if you want to restrict processes count.
