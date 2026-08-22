"""
description: All processes are killed when invokee dies
script: |
    pv = dict(stdout=PreviousOutput())
    for _ in range(2):
        pv = expect(run(), **pv)
        run_reset()
"""

import os
import shutil
import subprocess


def list_pids():
    return [int(pid) for pid in os.listdir("/proc") if pid.isdigit()]


subprocess.Popen([shutil.which("sleep"), "inf"])

print(list_pids())
