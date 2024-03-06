"""
description: Mount binds are readable and not always writable
assets:
  file: ""
  dir:
    file: ""
script: |
  touch("/space/readonly")
  bind_ro("file", "/space/readonly")

  touch("/space/readwrite")
  bind("file", "/space/readwrite")
  
  mkdir("/space/readonly_dir")
  bind_ro("dir", "/space/readonly_dir")
  
  mkdir("/space/readwrite_dir")
  bind("dir", "/space/readwrite_dir")

  expect(run())
"""

import os


open("/space/readonly")

try:
    open("/space/readonly", "w")
except OSError:
    pass
else:
    assert False, "Did not fail to open /space/readonly for writing"

open("/space/readwrite", "w")


os.listdir("/space/readonly_dir")

try:
    open("/space/readonly_dir/x", "w")
except OSError:
    pass
else:
    assert False, "Did not fail to open /space/readonly_dir/x for writing"

try:
    open("/space/readonly_dir/file", "w")
except OSError:
    pass
else:
    assert False, "Did not fail to open /space/readonly_dir/file for writing"

open("/space/readwrite_dir/x", "w")
open("/space/readwrite_dir/file", "w")
