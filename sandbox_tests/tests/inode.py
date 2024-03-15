"""
description: Inode number is not monotonic
script: |
    pv = dict(stdout=PreviousOutput())
    for i in range(2):
        pv = expect(run(context=i), **pv)
        run_reset()
"""

import os


with open("/space/test", "w") as f:
    pass

print(os.stat("/space/test").st_ino)
