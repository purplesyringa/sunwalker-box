"""
description: All processes are killed when invokee dies
script: |
  pv = {}
  for _ in range(2):
    _, _, pv = expect(run(), previous_values=pv, matching_stdout=True)
    run_reset()
"""

import os
import subprocess


def list_pids():
    return [int(pid) for pid in os.listdir("/proc") if pid.isdigit()]


subprocess.Popen(["/bin/sleep", "inf"])

print(list_pids())
