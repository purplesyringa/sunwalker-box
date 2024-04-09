Isolating cores
===============

There is a simple interface for advising the box and scheduler which cores are likely to be used to not spend some time when the core will be really used. The following two commands allow marking and unmarking supplied core respectively.

```shell
# sunwalker_box isolate --core {CORE}
# sunwalker_box free --core {CORE}
```

Note that cores are indexed from zero.

The scheduler is only advised not to use the supplied core, but is not obligated to do so. This means that on high load the testing results might be somewhat unstable. To actually prevent the scheduler from using cores, start kernel with `isolcpus` option.

If you use multiple cores --and you probably should use all but one or two cores for sunwalker if you are running it in production-- repeat the command for each core. This should only be run once (until reboot). Also, you most likely won't need releasing cores in production environment.
