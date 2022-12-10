"""
description: Pseudoterminals work and are reset correctly
runs: 2
expect:
  matching_stdout: true
"""

import os
import pty


result = b""


def read(fd):
    global result
    result += os.read(fd, 1024)
    return b""


# Make sure IDs are reset
pty.openpty()
print(os.listdir("/dev/pts"))


pty.spawn(["/usr/bin/echo", "Hello, world!"], read)

assert result == b"Hello, world!\r\n"
