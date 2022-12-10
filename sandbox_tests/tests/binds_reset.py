"""
description: Bind-mounts are removed on reset
assets:
  dir:
    file: text
preexec:
  - ~0 mkdir /space/dir
  - ~0 bind @dir /space/dir
  - ~0 bind @dir /var
runs: 2
pass_run_number: true
"""

import os
import sys


run = int(sys.argv[-1])

if run == 0:
    assert os.path.exists("/space/dir/file")
    assert os.path.exists("/var/file")
else:
    assert not os.path.exists("/space/dir")
    assert not os.path.exists("/var/file")
