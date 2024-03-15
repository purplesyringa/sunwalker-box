"""
description: /proc is mounted correctly
script: |
    expect(run())
"""

import os
import sys


for name in [os.getpid(), "self"]:
    with open(f"/proc/{name}/cmdline") as f:
        argv = f.read().split("\0")[:-1]
        expected_argv = [sys.executable] + sys.argv
        assert argv == expected_argv, f"{argv} != {expected_argv}"
