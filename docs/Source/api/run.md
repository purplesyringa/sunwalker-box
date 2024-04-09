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