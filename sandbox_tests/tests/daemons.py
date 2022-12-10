"""
description: All processes are killed when invokee dies
runs: 2
expect:
  matching_stdout: true
"""

import os
import subprocess
import sys
import time


def list_pids():
    return [int(pid) for pid in os.listdir("/proc") if pid.isdigit()]


subprocess.Popen(["/usr/bin/sleep", "inf"])

print(list_pids())
