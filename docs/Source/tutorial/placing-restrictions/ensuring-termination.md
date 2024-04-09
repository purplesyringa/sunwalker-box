Ensuring program termination
============================

Before we dive into enforcing time limits, let's talk about what these limits are and how to measure how much of them were taken.

There are usually three types of time: the CPU time, the idleness time, and the wall clock time.

_CPU time_ is the actual amount of time the program did something meaningful, _id est_ performed calculations and used the processor.

_Wall clock time_, also known as _real_ and _astronomical_ time, is the duration between program birth and death, as measured from the outside by wall clock (hence the name) or another external time source.

_Idleness time_ is the amount of time the program spent while waiting for IO or sleeping.

Wall clock time is essentially the sum of CPU and idleness times.

You may have encountered these times before, in `time` utility (both as shell builtin and a real executable):

```shell
$ time sleep 10s    # The bash builtin
real    0m10.002s
user    0m0.000s
sys     0m0.001s
$ \time sleep 10s   # External time utility
0.00user 0.00system 0:10.00elapsed 0%CPU (0avgtext+0avgdata 3684maxresident)k
0inputs+0outputs (0major+86minor)pagefaults 0swaps
```

Here, `user` and `sys` (or `system`) signify the CPU time spent in userspace and kernelspace respectively, and `elapsed` or `real` is the wall clock time.

In the "Hello world" example we can see these times in the response to the `run` request.

```json
{
    "command": "run",
    "payload": {
        "argv": ["/bin/echo", "Hello world!"],
        "stdio": { "stdout": "/space/stdout" }
    }
}
{
    "status": "Success",
    "data": {
        "verdict": { "kind": "Exited", "exit_code": 0 },
        "metrics": { "cpu_time": 0.00088, "real_time": 0.001788455, "idleness_time": 0.000908455, "memory": 397312 }
    }
}
```

Fields `cpu_time`, `real_time` and `idleness_time` show elapsed time in seconds. The program from this example took approximately 2 ms to terminate, used approximately 1 ms of CPU time and spent another 1 ms while waiting for IO.

However, measuring time like this is a bit inaccurate as the results may differ slightly between consequtive runs.

sunwalker-box already advises the OS scheduler not to use cores on which the boxes are running. However, the scheduler only _avoids_ these cores, and kernel threads can still use them. To advise kernel threads to avoid these cores, start kernel with the [`isolcpus={list,of,cores,to,avoid}`](https://docs.kernel.org/admin-guide/kernel-parameters.html) option.

`sunwalker_box start` reserves the core, if it hadn't been reserved already. You most likely won't need releasing cores in production environment, but it's possible to steal the core back from sunwalker:

```shell
# sunwalker_box free --core 1
```

Here `--core 1` tells to steal the second core from sunwalker-box and return it to the scheduler.

Note that launching more than one instance of sunwalker-box per core is harmful for this very reason.

---

To prevent denial-of-service attacks arising from never-terminating programs, you should enforce wall clock time limit, either by limiting it explicitly, or via limiting both CPU and idleness times. As of 2024, there is [no known way](https://en.wikipedia.org/wiki/Termination_analysis) of determining if the given program will ever halt or not for every program and its input.

There are two simple examples of programs that won't ever terminate: the infinite loop and the infinite wait. Here is their implementation in POSIX shell, but they can easily be translated to other languages.

```shell
$ while true; do true; done    # The infinite loop, which exhausts CPU
$ sleep inf                    # The infinite wait, which causes the box to appear silently hung
```

Infinite wait may also be encountered in deadlock situations, e.g. when two programs communicate and await each other's input.

You can set which limits to enforce with `limits` parameter like here:

```json
{
    "command": "run",
    "payload": {
        "argv": ...,
        "limits": {
            "cpu_time": 1.5,
            "idleness_time": 3,
            "real_time": 3.5,
        }
    }
}
```

This will set CPU time limit to 1.5 seconds, idleness time limit to 3 seconds, and wall clock time limit to 3.5 seconds. Note that real time limit is set to something _lower_ than the sum of CPU and idleness times. This is a feature: we can limit CPU time, idleness time, and their sum which is essentially a real time limit.

```ascii
 ^ CPU TL, s
 |
 4
\|
 +
 |\
 3 \  Real time should be below this line
 |  \
 |   \
 |    \      | Idleness time should be to the left of this line
 2     \     |
 |      \    |
 +-------+---+---------- CPU time should be below this line
 |        \  |
 1         \ |
 |  Valid   \|
 |   times   +
 |           |\
 0---1---2---3-+-4--> Idleness TL, s
                \
```

There are three subkinds of `LimitExceeded` verdict that correspond to the respective requested limit.

```json
{
    "command": "run",
    "payload": {
        "argv": ["/bin/sleep", "inf"],
        "limits": { "idleness_time": 1 }
    }
}
{
    "status": "Success",
    "data": {
        "verdict": { "kind": "LimitExceeded", "limit": "idleness_time" },
        "metrics": { "cpu_time": 0.00082, "real_time": 1.052056206, "idleness_time": 1.051236206, "memory": 405504 }
    }
}
```

You can also receive `cpu_time` and `real_time` in `limit` field.
