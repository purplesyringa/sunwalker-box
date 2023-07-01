"""
description: Binds are preserved after commit
assets:
    file: Pre-uploaded
    dir:
      file: Pre-uploaded 2
preexec:
  - ~0 touch /space/file
  - ~0 mkdir /space/dir
  - ~0 bind @file /space/file
  - ~0 bind @dir /space/dir
  - ~2 touch /space/file_ro /space/file_rw
  - ~2 mkdir /space/dir_ro /space/dir_rw
  - ~2 bind @file /space/file_rw
  - ~2 bind -ro @file /space/file_ro
  - ~2 bind @dir /space/dir_rw
  - ~2 bind -ro @dir /space/dir_ro
  - ~2 commit
runs: 4
pass_run_number: true
"""

import os
import sys


run = int(sys.argv[-1])

if run == 0:
    with open("/space/file") as f:
        assert f.read() == "Pre-uploaded"
    with open("/space/dir/file") as f:
        assert f.read() == "Pre-uploaded 2"
elif run == 1:
    assert not os.path.exists("/space/file")
    assert not os.path.exists("/space/dir")
elif run == 2:
    with open("/space/file_rw", "w") as f:
        f.write("Modified 1")
    with open("/space/dir_rw/file", "w") as f:
        f.write("Modified 2")
    with open("/space/dir_rw/test", "w") as f:
        f.write("Modified 3")
else:
    with open("/space/file_ro") as f:
        assert f.read() == "Modified 1"
    with open("/space/dir_ro/file") as f:
        assert f.read() == "Modified 2"
    with open("/space/dir_ro/test") as f:
        assert f.read() == "Modified 3"

    try:
        open("/space/file_ro", "w")
    except OSError:
        pass
    else:
        assert False, "Did not fail to open /space/file_ro for writing"

    try:
        open("/space/dir_ro/x", "w")
    except OSError:
        pass
    else:
        assert False, "Did not fail to open /space/dir_ro/x for writing"

    try:
        open("/space/dir_ro/file", "w")
    except OSError:
        pass
    else:
        assert False, "Did not fail to open /space/dir_ro/file for writing"
