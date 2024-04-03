User-level API
==============

The reference library implementation in Python is documented elsewhere (where exactly?). This is the JSON API reference.

The communication with the box is done via stdio based on request-response model. Here's a brief overview on our implementation:

```ascii
                                                .---------Response---------.
                                  .--Failure-->|  error <json-description>  |
+-----------Request-----------+  /              '--------------------------'
| <command> [<json-argument>] +-+
+-----------------------------+  \              .------Response------.
                                  '--Success-->|  ok [<json-result>]  |
                                                '--------------------'
```

Say, you want to request `hello` with two arguments `world` and `everyone` represented as an array. The example communication will look like this:

```json
hello ["world", "everyone"]
ok ["Hello, world!", "Hello, everyone!"]
hello 1984
error "Type mismatch: expected array, got integer"
hello
error "This command requires an argument"
```

This command may be documented as
> ### `hello [...names]` -- greet someone
> - `[...names]` list of strings -- whom to greet
>
> Returns list of strings where each output string is `Hello, {input_string}!`
>
> #### Example
> ```json
> hello ["world", "everyone"]
> ok ["Hello, world!", "Hello, everyone!"]
> ```

Due to some limitations, you probably wouldn't get a meaningful error message on malformed input. Please don't reinvent a wheel and use an existing library for JSON serialization and deserialization for your language. This also makes writing commands by hand more error-prone, so you may wish to create more friendly wrappers around this API.

Due to some other limitations request must _not_ contain literal newlines. This file will, however, use the newlines to prettify JSONs.


Filesystem manipulations
------------------------

The sandbox manages a scratch filesystem somewhere in the RAM, which has a user-writable `/space` directory to put user files to.

### `extpath` -- resolve internal root path

Returns path that can be used to access the internal root from outside of the box. Never changes while the box is alive

#### Example
```json
extpath
ok "/proc/191072/root/newroot"
```

### `bind {internal, external, ro}` -- create a file or directory mirror

- `external` path -- that is the path relative to the external root (what about supplied root?)
- `internal` path -- that is relative to the sandboxed root
- `ro` flag -- tells the box to make the bind read-only if set to true

Returns nothing.

The file/directory at the internal path must already exist inside the sandbox; if they don't, create them before. (What about mode bits?)

### **FIXME: Do not hardcode UIDs and GIDs.**

Sandbox user (and group) ids, as seen from external world are the following:
- 1, root
- 2, user

Please don't use any ids other than these for file permissions. Other ids may _or may not_ map into `nobody`. Who knows, this is an implementation detail!


Deprecated filesystem commands
------------------------------

Some filesystem manipulation commands are deprecated and can be implemented outside of the box via `extpath` request. Some of these commands are implemented in the reference library.

### `ls "/path/to/a/directory"` -- list the contents of the directory
  
Returns a JSON object with filenames as keys and objects satisfying
- `file_type` string -- any of `dir`, `file`, `symlink`, `block`, `char`, `fifo`, `socket`, `unknown`
- `len` integer -- object size in bytes
- `mode` integer -- access mode, in base 10. 0755 will be returned as 493

You can call `readdir` directly outside of the box on `extpath {path}`

### `cat {path, at, len}` -- return the contents of the part of the file as an array of byte values
- `path` path -- which file to read
- `at` integer -- starting offset
- `len` integer -- count of bytes to read

Seeking further than EOF is considered an error, reaching EOF before `len` is exhausted is not.

A length limit of `0` means unlimited. Only regular files can be read this way.

You can _check that file is really a regular file_, use `open` and then either `seek` + `read`, or `mmap` it directly.

### `mkdir {path, owner, mode}` -- create a directory at the given path
- `path` path -- where to create
- `owner` string -- "root" or "user"
- `mode` integer -- access mode, in base 10

Returns nothing.

You can create the directory and chown+chmod it from the outside.

### `mkfile {path, content, owner, mode}` -- create a regular file with the given bytes content
- `path` path -- where to create
- `content` list of bytes -- what to write
- `owner` string -- "root" or "user"
- `mode` integer -- access mode, in base 10

Returns nothing.

You can create the file and chown+chmod it from the outside.

### `mksymlink {link, target}` -- create a symlink with the given target
- `link` path -- where to put the link
- `target` path -- where the link points; may be nonexistent

Returns nothing.

You can create the link from outside with `symlinkat(2)`.


Persistence and leftovers
-------------------------

All modifications to the filesystem are temporary and are not propagated to the underlying chroot. Note that read-write binds to the external filesystem _do_ propagate changes, and the changes are visible to the subsequent runs even after reset, given that you rebind the directory -- which is done, e.g. after resetting to a committed state.

### `reset` -- reset sandbox to the initial state

Resets everything to the initial state: filesystem, PIDs, temporary files, network data, etc.

The filesystem is reset only after an explicit request. Make sure to request filesystem reset if you don't want to leave traces of prior launch in the box filesystem.

The filesystem is reset to committed state if it exists, or to the initial state.

### `commit` -- commit filesystem

You can also `commit` a filesystem to save its state as a reference state for next `reset` invocations. For a number of reasons (which exactly?) you can't commit filesystem more than once and reset to the initial state without restarting the box.


Processes controlling
---------------------

### Type `<stdio>` -- stdio file paths
- `stdin` string -- input file
- `stdout` string -- output file
- `stderr` string -- errput file

All fields are optional.

### Type `<limits>` -- per-process limits
- `real_time_limit` float -- how much wall time the program may use, in seconds
- `cpu_time_limit` float -- how much CPU time the program may use, in seconds
- `idleness_time_limit` float -- how much time the program may spend in iowait in total, in seconds
- `memory_limit` integer -- how much RAM the program may use, in bytes
- `processes_limit` positive integer -- how many processes the program may start at once including itself

All fields are optional. Unset field means that the limit for this field will not be enforced.

### Type `<metrics>` -- completed process metrics
- `real_time` float
- `cpu_time` float
- `idleness_time` float
- `memory` integer

Approximately how much of the limits the program used, in the same units as the corresponding limits.

Note the word "approximately" -- even when the limit is exceeded, i.e. `verdict` is _not_ `Exited`, the corresponding metric might be slightly _less_ than the limit. How to handle this discrepancy is your choice, but **do not use metrics to check if a limit has been exceeded**.

### Enum `verdict` -- program termination reason
- `limit_verdict` string -- the verdict discriminator
- `exit_code?` optional integer -- supplementary data

Currently supported variants are:

#### `Exited(exit_code)` -- the program exited withoud exceeding limits
- `limit_verdict` -- `"OK"`
- `exit_code` -- integer from `0` to `255`; `0` typically indicates successful termination
#### `Signaled(signal)` -- the program was terminated by a signal
- `limit_verdict` -- `"Signaled"`
- `exit_code` -- negated `signal` number, e.g. `-9` for `SIGKILL`
#### `Limited(limit)` -- the program has exceeded a limit
- `limit_verdict` -- `"{limit}LimitExceeded`, e.g. `"MemoryLimitExceeded"`. The `limit` value is one of `RealTime`, `CPUTime`, `IdlenessTime`, `Memory`. Note that there is no `ProcessesLimitExceeded` verdict.
- `exit_code` -- undefined value. May or may not be present

### `run {argv, env?, **stdio, **limits}` -- run sandboxed process
- `argv` list of strings -- a list of arguments, including the path/name of the program as the first argument
- `env?` optional string to string dictionary -- the new environment of the process. Environment variables are inherited if and only if this argument missing.
- `**stdio` values -- unpacked stdio file paths
- `**limits` values -- unpacked per-process limits

Returns `{**verdict, **metrics}`.

The program is always executed with working directory `/space`.

This command is blocking and returns only when the program terminates. To prevent DoS attack, CPU time and processes count must necessarily be limited. Limiting real time and/or idleness time is also recommended, but not strictly necessary, e.g. if you kill the box on timeout manually.

#### Example: a simple program

```json
run {
    "argv": ["/bin/echo", "nyaa"],
    "stdout": "/space/out"
}
ok {
    "limit_verdict": "OK",
    "exit_code": 0,
    "real_time": 0.000590219,
    "cpu_time": 0.000489,
    "idleness_time": 0.000101219,
    "memory": 331776
}
extpath
ok "/proc/230463/root/newroot"
```

This result means that the verdict is `Exited(0)`, and the program has used (approximate values) 0.5 ms CPU time, 0.1 ms of idleness itme, 0.6 ms of real time and 324 KiB of memory. We can now confirm that this file contains the desired output:

```shell
# xxd /proc/230463/root/newroot/space/out
00000000: 6e79 6161 0a                             nyaa.
```

#### Example: exceeding limits

You can exceed idleness time limit with a call to `sleep(1)`,...

```json
run {
    "argv": ["/bin/sh", "-c", "sleep inf"],
    "idleness_time_limit": 1
}
ok {
    "limit_verdict": "IdlenessTimeLimitExceeded",
    "exit_code": -1,
    "real_time": 1.050719835,
    "cpu_time": 0.000419,
    "idleness_time": 1.050300835,
    "memory": 331776
}
```

...and can exceed CPU time limit with a simple infinite loop.

```json
run {
    "argv": ["/bin/sh", "-c", "while true; do :; done"],
    "cpu_time_limit": 1
}
ok {
    "limit_verdict": "CPUTimeLimitExceeded",
    "exit_code": -1,
    "real_time": 1.003663311,
    "cpu_time": 1.001798,
    "idleness_time": 0.001865311,
    "memory": 331776
}
```

Real time limit can be exceeded too.

```json
run {
    "argv": [
        "/bin/sh",
        "-c",
        "sleep .3; while true; do :; done"
    ],
    "real_time_limit": 1
}
ok {
    "limit_verdict": "RealTimeLimitExceeded",
    "exit_code": -1,
    "real_time": 1.000655017,
    "cpu_time": 0.698518,
    "idleness_time": 0.302137017,
    "memory": 483328
}
```

Exceeding memory limits is somewhat tricky if we have only busybox sh:

```json
run {
    "argv": ["/bin/sh", "-c", "echo `yes`"],
    "memory_limit": 1000000000
}
ok {
    "limit_verdict": "MemoryLimitExceeded",
    "exit_code": -1,
    "real_time": 38.683770322,
    "cpu_time": 38.602746,
    "idleness_time": 0.081024322,
    "memory": 999997440
}
```

You can even run a fork bomb inside it!

```json
run {
    "argv": [
        "/bin/sh",
        "-c",
        "fork(){ fork|fork& }; fork"
    ],
    "processes_limit": 100
}
ok {
    "limit_verdict": "OK",
    "exit_code": 0,
    "real_time": 0.001289305,
    "cpu_time": 0.000911,
    "idleness_time": 0.000378305,
    "memory": 671744
}
```

Note that processes limit is still there, but handling process spawning error happens on the user side, therefore, ProcessesLimitExceeded is a nonexistent verdict.
