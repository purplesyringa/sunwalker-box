Hello, world!
=============

The box manipulates the system configuration quite a bit, so all commands have to be run under root.

[Build](../building.html) sunwalker-box, get root access and you're ready to use it.

Unlike typical sandboxing solutions that are configured via command-line arguments, sunwalker-box is designed to be a long-running process that is controlled by a simple [JSONL](https://jsonlines.org/) protocol via standard input/output. Every request and response is a JSON object and occupies one line. However, for readability purposes, we will pretty-format the requests and responses in this documentation.

Starting the box is easy (`--core 1` tells the box to run on the second core):

```shell
# sunwalker_box start --core 1
```

Or, if you wish to use Docker for environment, you can start it like this:

```shell
$ docker run --privileged --cgroupns=host -it alpine
# sunwalker_box start --core 1
```

If your setup is correct, the box will just silently wait for user input. You can terminate the box at any time with `^C`. The box will perform a proper cleanup.

Let's run a simple "hello world" with [`run`](../api/run.html) request inside the box

```json
{ "command": "run", "payload": { "argv": ["/bin/echo", "Hello world!"] } }
{
    "status": "Success",
    "data": {
        "verdict": { "kind": "Exited", "exit_code": 0 },
        "metrics": { "cpu_time": 0.000883, "real_time": 0.001790828, "idleness_time": 0.000907828, "memory": 401408 }
    }
}
```

The status is `Exited` with exit code `0` which indicates a successful process termination. The box responds with some metrics, but it does not provide the output.

The sandboxed program is run under a separate user and has no rights to read and write in different places. However, the sandboxed filesystem has a special directory `/space` where you can store your assets. We can redirect stdout there.

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

The sandboxed filesystem can be accessed from the outside: you can retrieve the sandboxed root with the [`extpath`](../api/extpath.html) request:

```json
{ "command": "extpath" }
{ "status": "Success", "data": "/proc/2209239/root/newroot" }
```

We can examine this root:

```shell
# extpath=/proc/2209239/root/newroot
# ls -a $extpath/
.  ..  bin  boot  dev  etc  home  lib  lib64  lost+found  mnt  nix  opt  proc  root  run  sbin  space  srv  tmp  usr  var
# ls -a /
.  ..  bin  boot  dev  etc  home  lib  lib64  lost+found  mnt  nix  opt  proc  root  run  sbin  srv  sys  tmp  usr  var
```

The sandboxed root has dangerous paths hidden and has a new directory `/space`. We can now grab the output:

```shell
# ls -a $extpath/space
.  ..  stdout
# hexdump -C $extpath/space/stdout
00000000  48 65 6c 6c 6f 20 77 6f  72 6c 64 21 0a           |Hello world!.|
0000000d
```

You can also put stdin and the solution there...

```shell
# echo 'print(sum(map(int, input().split())))' > $extpath/space/a.py
# echo '1 2 3 4 5' > $extpath/space/stdin
```

...run the program...

```json
{
    "command": "run",
    "payload": {
        "argv": ["/usr/bin/python3", "a.py"],
        "stdio": { "stdin": "/space/stdin", "stdout": "/space/stdout" }
    }
}
{
    "status": "Success",
    "data": {
        "verdict": { "kind": "Exited", "exit_code": 0 },
        "metrics": { "cpu_time": 0.03236, "real_time": 0.173163455, "idleness_time": 0.140803455, "memory": 7544832 }
    }
}
```

...and inspect its output:

```shell
# ls -a $extpath/space
.  ..  a.py  stdin  stdout
# hexdump -C $extpath/space/stdout
00000000  31 35 0a                                          |15.|
00000003
```

Bear in mind that the sandbox does _not_ clear leftover files from the sandboxed filesystem unless you explicitly call [`reset`](../api/reset.html).

```json
{ "command": "reset" }
{ "status": "Success", "data": null }
```

`/space` is now totally empty as it was when the box started and the same box can be reused to run the next executable, e.g. another submission.

```shell
# ls -a $extpath/space
.  ..
```
