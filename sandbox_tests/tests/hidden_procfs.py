"""
description: Dangerous files and directories under /proc are hidden
script: |
  expect(run())
"""

import os


with open("/proc/stat") as f:
    assert f.read() == "", "/proc/stat is not empty"

try:
    open("/proc/stat", "w")
except IOError:
    pass
else:
    assert False, "Did not fail to open /proc/stat for writing"


assert os.listdir("/proc/irq") == [], "/proc/irq is not empty"

try:
    open("/proc/irq/test", "w")
except IOError:
    pass
else:
    assert False, "Did not fail to open /proc/irq/test for writing"
