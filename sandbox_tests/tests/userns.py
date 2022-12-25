"""
description: Running in userns
"""

import os


assert os.getuid() == 1000, os.getuid()
assert os.getgid() == 1000, os.getgid()
assert os.getgroups() == [1000], os.getgroups()


with open("/proc/self/uid_map") as f:
    for line in f:
        inner, outer, length = map(int, line.split())
        assert outer != 0, "Internal root is mapped to external root"


with open("/proc/self/gid_map") as f:
    for line in f:
        inner, outer, length = map(int, line.split())
        assert outer != 0, "Internal root group is mapped to external root group"
