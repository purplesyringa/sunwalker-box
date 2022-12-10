"""
description: Inode number is not monotonic
runs: 2
expect:
  matching_stdout: true
"""

import os


with open("/space/test", "w") as f:
    pass

print(os.stat("/space/test").st_ino)
