"""
description: Is running in a small pidns
runs: 10
expect:
  matching_stdout: true
"""

import os


def list_pids():
    return [int(pid) for pid in os.listdir("/proc") if pid.isdigit()]


pids = list_pids()

assert len(pids) <= 5 and max(pids) <= 5

print(pids)
