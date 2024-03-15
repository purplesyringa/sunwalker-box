"""
description: Zombies are reaped
script: |
    for i in range(15):
        expect(run(context=i))
        run_reset()
"""

import os
import subprocess
import sys
import time


def list_pids():
    return [int(pid) for pid in os.listdir("/proc") if pid.isdigit()]


if sys.argv[-1] == "stage2":
    subprocess.Popen(["/bin/true"])
else:
    old_pids = list_pids()
    subprocess.run([sys.executable] + sys.argv + ["stage2"], check=True)
    time.sleep(0.1)
    new_pids = list_pids()
    assert old_pids == new_pids, f"{old_pids} != {new_pids}"
