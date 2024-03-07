"""
description: memfds are subject to memory limit
script: |
  expect(run(memory_limit=parse_size("20 MiB")), limit_verdict="MemoryLimitExceeded")
"""

import os

for i in range(20):
    with open(os.memfd_create(f"test{i}"), "wb") as f:
        for _ in range(1024):
            f.write(b"\x00" * 1024)
