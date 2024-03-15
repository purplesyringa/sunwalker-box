"""
description: memfds are subject to memory limit
script: |
    expect(run(limits=Metrics(memory="20 MiB")), verdict=Limited(Limit.memory))
"""

import os

with open(os.memfd_create("test"), "wb") as f:
    for _ in range(20 * 1024):
        f.write(b"\x00" * 1024)
