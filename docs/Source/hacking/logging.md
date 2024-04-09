Debug logs
==========

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
