"""
description: Bind-mounts are removed on reset
assets:
  dir:
    file: text
script: |
  mkdir("/space/dir")
  bind("dir", "/space/dir")
  bind("dir", "/var")
  expect(run(input="0"))
  run_reset()
  expect(run(input="1"))
"""

import os

run = int(input())

if run == 0:
    assert os.path.exists("/space/dir/file")
    assert os.path.exists("/var/file")
else:
    assert not os.path.exists("/space/dir")
    assert not os.path.exists("/var/file")
