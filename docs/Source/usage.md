Using sunwalker-box
===================

> TL;DR: Isolate the cores you want sunwalker-box to run user processes on with `sunwalker_box isolate --core {CORE}`, then start the sandbox with `sunwalker_box start --core {CORE}` (but you should add a few more options for security).

The box manipulates the system configuration quite a bit, so all commands have to be run under root. If, for some reason, you need to run sunwalker-box in Docker (and that's very, very inefficient and makes absolutely no sense if you're spawning a container per user submission because Docker's just duplicating what sunwalker-box does, just worse), `--privileged --cgroupns=host` suffices.

All command-line invocations of the box follow this simple pattern:

```shell
# sunwalker_box [<options>] <command> [<args>]
```


Logging
-------

Use `--logs <level>` option to enable logging for a command. You can also use the `SUNWALKER_BOX_LOG` environment variable if for some reason you don't want to ponder over command line. The command line setting takes precedence over environment variable one.

Here is an example log on `notice` level: 

```shell
# sunwalker_box --logs notice isolate --core 1
[main:cgroups   ] Creating cgroup

# SUNWALKER_BOX_LOG=notice sunwalker_box free --core 1
[main:cgroups   ] Deleted manager successfully
[main:cgroups   ] Deleted sunwalker-box-core-1 successfully
```

There are four logging levels:

| Level | Description |
|-------|-------------|
| `none` | No logs will be shown. Currently the default mode |
| `impossible` | Only critical security errors will be shown. They mean that the box can not guarantee its safety for this very invocation. If you encounter this behavior, please file a bug report |
| `warn` | Warnings will also be printed. This may show some additional information for tinkering with `impossible` conditions and some strange behaviors |
| `notice` | The most verbose level, almost every thing the box does is traced and is primarily used for debugging the box |



Isolating cores
---------------

There is a simple interface for advising the box and scheduler which cores are likely to be used to not spend some time when the core will be really used. The following two commands allow marking and unmarking supplied core respectively.

```shell
# sunwalker_box isolate --core {CORE}
# sunwalker_box free --core {CORE}
```

Note that cores are indexed from zero.

The scheduler is only advised not to use the supplied core, but is not obligated to do so. This means that on high load the testing results might be somewhat unstable. To actually prevent the scheduler from using cores, start kernel with `isolcpus` option.

If you use multiple cores --and you probably should use all but one or two cores for sunwalker if you are running it in production-- repeat the command for each core. This should only be run once (until reboot). Also, you most likely won't need releasing cores in production environment.


Running
-------

After registering the cores, you can finally start a sunwalker box instance using a command as simple as:

```shell
# sunwalker_box start --core {CORE} [<additional-options>]
```

You will most likely need to pass more options to keep the sandbox secured, though. Most importantly, you will need to setup a chroot environment and pass a path to it using `--root {PATH}`. You might also want to adjust the amount of disk space the box is allowed to use using `--quota-inodes {INODES} --quota-space {BYTES}`. The defaults are 1024 inodes and 30 MiB respectively; you might want to increase or decrease those, depending on your usecase. Note that unless you use `commit`, the limit is only enforced approximately.

If, after running the `start` command, sunwalker quietly awaits input, you're doing it right and sunwalker has created an empty sandbox. To actually *do* anything with the box, you issue commands to sunwalker via stdin, as if you used, say, memcached. To stop the sandbox, just `^C` or `^D` it--all resources will be cleaned up automatically.

See [this page](userapi) for commands reference.

