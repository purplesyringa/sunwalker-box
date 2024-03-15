"""
description: memfds have expected names that can collide
script: |
    expect(run())
"""

import mmap
import os

fd1 = os.memfd_create("test")
fd2 = os.memfd_create("test")

os.write(fd1, b"\x00" * 4096)
os.write(fd2, b"\x00" * 4096)

map1 = mmap.mmap(fd1, 4096)
map2 = mmap.mmap(fd2, 4096)

with open("/proc/self/maps") as f:
    assert f.read().count("/memfd:test (deleted)\n") == 2
