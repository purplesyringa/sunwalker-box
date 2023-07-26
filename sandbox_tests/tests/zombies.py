"""
description: Zombies are reaped
"""

import os
import subprocess
import sys
import time


def list_pids():
    return [int(pid) for pid in os.listdir("/proc") if pid.isdigit()]


if sys.argv[-1] == "stage2":
    subprocess.Popen(["/usr/bin/true"])
else:
    old_pids = list_pids()
    subprocess.run([sys.executable] + sys.argv + ["stage2"], check=True)
    time.sleep(0.1)
    new_pids = list_pids()
    assert old_pids == new_pids, f"{old_pids} != {new_pids}"
