"""
description: Cannot signal or access fds of other processes
script: |
  expect(run())
"""

import os


def list_pids():
    return [int(pid) for pid in os.listdir("/proc") if pid.isdigit()]


for pid in list_pids():
    if pid != os.getpid():
        try:
            os.kill(pid, 0)
        except PermissionError:
            pass
        else:
            assert False, f"Did not fail to signal PID {pid}"

        try:
            os.listdir(f"/proc/{pid}/fd")
        except PermissionError:
            pass
        else:
            assert False, f"Did not fail to list fds of PID {pid}"
