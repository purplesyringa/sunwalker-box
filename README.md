# sunwalker-box

This is a sandbox for running untrusted programs completely isolated, primarily for competitive programming competitions. This sandbox is used by sunwalker, but may just as well be used for your projects.

Licensed under Apache 2.0.


## Why sunwalker-box?

> TL;DR: sunwalker-box is more secure than some sandboxes and faster than others, provided that the invoked tasks are homogenous, that is, the same program is invoked in the same environment with slightly different configuration, e.g. input.

Most general-purpose sandboxes prioritize protection from permanent damage and don't care if the sandboxed process causes denial of service, e.g. by allocating lots of memory, using all cores of the CPU, or running a fork bomb.

They are also usually optimized for long-running tasks, when the time the sandbox takes to start does not really matter. For instance, Docker and Podman take about half a second to run hello-world.

In contrast, competitive-programming-themed sandboxes typically protect against DoS attacks and common vulnerabilities, but little else: there are often ways to circumvent some of protections using slightly non-trivial OS features. They are also seldom extensible.

Finally, sandboxes seldom prioritize efficiency. We can do much better than recreating a sandbox and restarting the same program from the filesystem a hundred times. And while tricks such as preforking might not increase the performance by a lot, optimizations do accumulate.


## Building

sunwalker-box supports x86-64 (AMD64) and aarch64 (ARM64) architectures and requires Linux 5.19+ on x86-64 and Linux 6.2+ on aarch64.

Both build methods generate a `sunwalker_box` executable in the current directory. The executable is statically linked and relatively small (around a megabyte, and smaller in compressed form), so it can be copied to any Linux machine and run without requiring any additional libraries or dependencies.


### With Docker

For x86-64, you can use the `Dockerfile` provided in this repository:

```shell
$ id="$(docker create "$(docker build -q .)" a)" && docker cp "$id:/sunwalker_box" sunwalker_box && docker rm "$id"
```

This generates `sunwalker_box` binary.


### With Nix

For x86-64, you can use the `flake.nix` provided in this repository:

```shell
$ nix build
```

You can also build sunwalker-box without flakes, and it's just as simple:

```shell
$ nix-build
```

Both commands will produce `./result/bin/sunwalker-box` binary.


### Without Docker

For aarch64, or if you don't want to use Docker, you will need to install the following dependencies:

- Rust, with:
  - Toolchain `nightly-<architecture>-unknown-linux-gnu`, provided by e.g. `rustup toolchain install nightly-x86_64-unknown-linux-gnu`,
  - Target `<target>-unknown-linux-musl`, provided by e.g. `rustup +nightly target add x86_64-unknown-linux-musl`,
  - Component `rust-src`, provided by `rustup component add rust-src`
- GNU make
- GNU C++ compiler, provided on Ubuntu by `g++`
- Linux userspace headers, provided on Ubuntu as `libc6-dev`, on Arch Linux as `linux-api-headers`, and on Alpine as `linux-headers`
- binutils
- Python 3
- `ruby`, provided on Ubuntu by `ruby`
- `gem`, provided on Ubuntu by `ruby-rubygems`
- Ruby headers, provided on Ubuntu by `ruby-dev`
- `seccomp-tools`, provided by `gem install seccomp-tools`
- `racc` (dependency of `seccomp-tools`), provided by `gem install racc`
- (aarch64 only) Linux kernel headers, provided on Ubuntu by `linux-headers-$(uname -r)`,
- (sandbox-tests only) `musl-gcc`, provided on Ubuntu by `musl-tools`,
- (sandbox-tests only) `pyyaml` python package, provided on Alpine by `py3-yaml`

To build sunwalker-box, use:

```shell
$ make
```

This generates a `sunwalker_box` executable in the current directory.

Cross-compilation for x86-64 is supported by passing `CC=x86_64-linux-gnu-gcc` (or the corresponding cross-compiler for your Linux distribution) to `make`. For aarch64, sunwalker-box should be built natively on the target machine, as it includes a kernel module which is dependent on the exact kernel version.


## Using

> TL;DR: Isolate the cores you want sunwalker-box to run user processes on with `sunwalker_box isolate --core {CORE}`, then start the sandbox with `sunwalker_box start --core {CORE}` (but you should add a few more options for security).

Sunwalker manipulates the system configuration quite a bit, so all commands have to be run under root. If, for some reason, you need to run sunwalker-box in Docker (and that's very, very inefficient and makes absolutely no sense if you're spawning a container per user submission because Docker's just duplicating what sunwalker-box does, just worse), `--privileged --cgroupns=host` suffices.

Firstly, reserve the cores you want sunwalker to use exclusively for running untrusted code. The preferred way to do this is to start the Linux kernel with the `isolcpus` option. If you can't or won't use `isolcpus`, sunwalker will work fine anyway, but then Linux might use the cores for kernel tasks, so the testing results might be somewhat unstable.

Regardless of whether you used `isolcpus`, enable sunwalker to use the core via

```shell
# sunwalker_box isolate --core {CORE}
```

Note that the cores are indexed from zero.

If you use multiple cores (you probably should use all but one or two cores for sunwalker if you are running it in production), repeat the command for each core. This should only be run once (until reboot).

To steal the core back from sunwalker, use

```shell
# sunwalker_box free --core {CORE}
```

Again, you most likely won't need this in production.

After registering the cores, you can finally start a sunwalker box instance using a command as simple as:

```shell
# sunwalker_box start --core {CORE}
```

You will most likely need to pass more options to keep the sandbox secured, though. Most importantly, you will need to setup a chroot environment and pass a path to it using `--root {PATH}`. You might also want to adjust the amount of disk space the box is allowed to use using `--quota-inodes {INODES} --quota-space {BYTES}`. The defaults are 1024 inodes and 30 MiB respectively; you might want to increase or decrease those, depending on your usecase. Note that unless you use `commit`, the limit is only enforced approximately.

If, after running the `start` command, sunwalker quietly awaits input, you're doing it right and sunwalker has created an empty sandbox. To actually *do* anything with the box, you issue commands to sunwalker via stdin, as if you used, say, memcached. To stop the sandbox, just <kbd>^C</kbd> it--all resources will be cleaned up automatically.


### Commands

The requests and responses are JSONs. Requests typically look like `{"command":"<command-name>", "payload":...}` and are terminated with a newline. The box responses either with `{"status":"Failure", "error":...}` in case of error, and `{"status":"Success", "data":...}`.


### Controlling processes

The command `run` starts a process inside the sandbox. It takes a JSON object with the following options as an argument:

- `argv` (required) -- a list of arguments, including the path/name of the program as the first argument, e.g. `"argv": ["program_name", "arg1", ...]`.
- `stdio` (optional) -- a dict of `stdin`, `stdout`, `stderr` (each key is optional) -- to which files standard streams are to be redirected. If missing, uses `/dev/null` (must be present inside the chroot environment). Example: `"stdin": "/space/input.txt"`.
- `limits` (optional) -- a dictionary, how much of resource the program may use
  - `real_time` (optional) -- wall time, in seconds, e.g. `"real_time": 1.5`.
  - `cpu_time` (optional) -- CPU time, in seconds, e.g. `"cpu_time": 1.0`.
  - `idleness_time` (optional) -- total time spent in iowait, in seconds, e.g. `"idleness_time": 1.0`.
  - `memory` (optional) -- RAM usage, in bytes, e.g. `"memory": 128000000`.
  - `processes` (optional) -- spawned processes, including itself, e.g. `"processes": 64`. Must be positive.
- `env` (optional) -- the new environment of the process as a string-to-string dictionary. If missing, environment variables are inherited. If passed, all old environment variables are deleted.

The fullest `run` command example is, pretty-printed
```json
{
  "command": "run",
  "payload": {
    "argv": ["/bin/echo", "nyaa"],
    "env": {
      "LC_ALL": "C",
      "LANG": "en_US",
    },
    "limits": {
      "cpu_time": 1.0,  // 1 second
      "idleness_time": 0.5,  // 500 ms
      "real_time": 1.5,  // 1.5 seconds
      "memory": 1024000,  // slightly greater than 1 MB
      "processes": 1,  // disallow forking
    },
    "stdio": {
      "stdin": "/dev/null",
      "stdout": "/space/out",
      "stderr": "/dev/null",
    }
  }
}
```

To prevent DoS attacks, CPU time and processes limits must necessarily be set. Limiting real and/or idleness time is also recommended, but not strictly necessary, e.g. if you kill the box on timeout manually.

The program is always executed with working directory `/space`.

This command is blocking. When the program exits or a limit expires, a `Success` status is returned (even if a limit expired) with a JSON-object value with the following properties:

- `verdict` -- either of the following:
  - `{"kind":"Exited", "exit_code": <exit-code>}` -- the program exitted without exceeding limits, `exit_code` is the exit code of the program from `0` to `255` (`0` typically indicates success).
  - `{"kind":"Signaled", "signal_number": <signal-number>}` -- the program was terminated by a signal, `signal_number` is plain signal number, e.g. `9` for `SIGKILL`.
  - `{"kind":"LimitExceeded", "limit": <limit>}` -- the program used more `<limit>` (may be one of `real_time`, `cpu_time`, `idleness_time` and `memory`) than allowed
- `metrics` -- a dictionary with keys `real_time`, `cpu_time`, `idleness_time`, `memory` -- approximately how much wall-clock time/CPU time/iowait time/memory the program used, in the same units as the corresponding limits (i.e. seconds or bytes). Note the word "approximately" -- even when the limit is exceeded, i.e. verdict is not `Exited`, the corresponding metric might be slightly less than the limit. How to handle this discrepancy is your choice, but **do not use metrics to check if a limit has been exceeded**.

After the process finishes, you can run another program in the same box in the same way. And if you want to run another program (or the same program with different input, you get the gist), but without the leftovers of the previous processes (PIDs, temporary files, network data, etc.), don't restart the sandbox! Instead, use `reset`, which efficiently restores the box to the original state as if sunwalker-box was just invoked, and proceed without restarting sunwalker-box. This is much more efficient. And if you need to revert to a more mature state, `commit` is available.


### Managing file system

Filesystem-related commands modify the virtual overlay filesystem rather than the chroot environment, so all modifications are temporary and are not propagated to disk (that is, unless you are low on memory and use swap). They are also rolled back when the `reset` command is issued, either to the clean state at the start of `sunwalker-box`, or to the state at the moment when `commit` is invoked.

Sunwalker creates a user-writable `/space` directory to put user files to.

Unless specified otherwise, the paths are relative to the box chroot environment.

- `{"command":"extpath"}` -- returns a path by which the root of sandboxed filesystem can be accessed from outside.
- `{"command":"bind", "payload":{"source": "/path/outside/the/box", "mountpoint": "/path/inside/the/box", "readonly": false/true}}` -- creates a read-write or a read-only mirror of an external directory or file. The file/directory must already exist inside the sandbox; if they don't, use `mkfile`/`mkdir` before.

Any other filesystem-related operations can be done from user side with `extpath` command and in the same way as if they were done in a regular filesystem. The only difference is in UIDs and GIDs: please don't use ids other than 1 (root) and 2 (user) as they may or _may not_ be mapped into `nobody:nogroup`.
