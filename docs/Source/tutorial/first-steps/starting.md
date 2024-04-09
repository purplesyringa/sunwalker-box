Running
-------

After [registering the cores](core-isolation.html), you can finally start a sunwalker box instance using a command as simple as:

```shell
# sunwalker_box start --core {CORE} [<additional-options>]
```

You will most likely need to pass more options to keep the sandbox secured, though. Most importantly, you will need to setup a chroot environment and pass a path to it using `--root {PATH}`. You might also want to adjust the amount of disk space the box is allowed to use using `--quota-inodes {INODES} --quota-space {BYTES}`. The defaults are 1024 inodes and 30 MiB respectively; you might want to increase or decrease those, depending on your usecase. Note that unless you use `commit`, the limit is only enforced approximately.

If, after running the `start` command, sunwalker quietly awaits input, you're doing it right and sunwalker has created an empty sandbox. To actually *do* anything with the box, you issue commands to sunwalker via stdin, as if you used, say, memcached. To stop the sandbox, just `^C` or `^D` it--all resources will be cleaned up automatically.
