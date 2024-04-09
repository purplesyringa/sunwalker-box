Troubleshooting
===============

(TODO is this really needed) Don't forget to mount `tmpfs` over `tmp` to not exhaust disk space at `/`:

```shell
# mount -t tmpfs tmpfs tmp
```

---

```shell
# sunwalker_box start --core 1
Sanity checks failed

Caused by:
    No such file or directory (os error 2)
```

`procfs` is not mounted under `/proc`. Solution:

```shell
# mount -t proc proc /proc
```

---

```shell
# sunwalker_box start --core 1
Sanity checks failed

Caused by:
    0: cgroups are not available at /sys/fs/cgroup
    1: ENOENT: No such file or directory
```

`sysfs` and/or `cgroupv2` is not mounted. Solution:

```shell
# mount -t sysfs sys /sys
# mount -t cgroup2 cgroup2 /sys/fs/cgroup
```

---

```shell
# sunwalker_box start --core 1
Failed to start box

Caused by:
    0: Failed to create /dev copy
    1: /oldroot/dev/full does not exist (or could not be accessed)
    2: No such file or directory (os error 2)
```

`devtmpfs` is not mounted. Solution:

```shell
# mount -t devtmpfs dev dev
```

---

```shell
# sunwalker_box start --core 1
File descriptor 10 is not CLOEXEC
Failed to start box

Caused by:
    Manager terminated too early
```

You use `strace`, `perf trace`, debugging tools, or misconfigured shell. Try using a clean environment

---
