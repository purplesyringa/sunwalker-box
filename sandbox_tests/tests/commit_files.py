"""
description: Files are preserved after commit
preexec:
  - ~1 commit
runs: 4
pass_run_number: true
"""

import os
import sys


run = int(sys.argv[-1])

if run == 0:
    with open("/space/run0", "w") as f:
        f.write("Run 0")
elif run == 1:
    assert not os.path.exists("/space/run0")
    with open("/space/run1", "w") as f:
        f.write("Run 1")
elif run == 2:
    assert not os.path.exists("/space/run0")
    with open("/space/run1") as f:
        assert f.read() == "Run 1"
    with open("/space/run2", "w") as f:
        f.write("Run 2")
else:
    assert not os.path.exists("/space/run0")
    with open("/space/run1") as f:
        assert f.read() == "Run 1"
    assert not os.path.exists("/space/run2")
