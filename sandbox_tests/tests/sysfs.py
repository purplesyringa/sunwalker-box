"""
description: sysfs is not mounted
"""

import os

assert not os.path.exists("/sys"), "/sys exists"


with open("/proc/self/mountinfo") as f:
    for line in f:
        assert "sysfs" not in line or "sysfs.py" in line, line
