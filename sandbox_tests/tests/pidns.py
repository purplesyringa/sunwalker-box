"""
description: Is running in a small pidns
script: |
    stdout="Hello!\n[1, 2, 3]\n"

    for _ in range(10):
        expect(run(), stdout=stdout)
        run_reset()
"""

import os


def list_pids():
    return [int(pid) for pid in os.listdir("/proc") if pid.isdigit()]


print("Hello!")
print(list_pids())
