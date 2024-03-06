"""
description: Binds are preserved after commit
assets:
    file: Pre-uploaded
    dir:
      file: Pre-uploaded 2
script: |
  touch("/space/file")
  bind("file", "/space/file")
  
  mkdir("/space/dir")
  bind("dir", "/space/dir")
  
  expect(run(input="0"))
  run_reset()
  expect(run(input="1"))
  run_reset()

  touch("/space/file_ro")
  bind_ro("file", "/space/file_ro")
  
  touch("/space/file_rw")
  bind("file", "/space/file_rw")
  
  mkdir("/space/dir_ro")
  bind_ro("dir", "/space/dir_ro")
  
  mkdir("/space/dir_rw")
  bind("dir", "/space/dir_rw")
  commit()
  
  expect(run(input="2"))
  run_reset()
  expect(run(input="3"))
  run_reset()
"""

import os

run = int(input())

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
