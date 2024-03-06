"""
description: Inode number is not monotonic
script: |
  pv = {}
  for i in range(2):
    _, _, pv = expect(run(context=i), previous_values=pv, matching_stdout=True)
    run_reset()
"""

import os


with open("/space/test", "w") as f:
    pass

print(os.stat("/space/test").st_ino)
