"""
description: memfds are subject to disk quotas
quotas:
  space: 10000
script: |
  expect(run())
"""

import errno
import os

f = open(os.memfd_create("test"), "wb")

for _ in range(1024):
    try:
        f.write(b"\x00" * 1024)
    except OSError as e:
        if e.errno == errno.ENOSPC:
            break
        else:
            raise
else:
    assert False, "Did not fail to write"
