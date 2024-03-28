"""
description: Is running in a small pidns and pid is preserved during prefork
slow: true
script: |
    for _ in range(10):
        expect(run(), stdout="3\n3\n[1, 2, 3]\n")
        run_reset()

    pid = prefork()
    expect(pid, verdict=Suspended)
    for i in range(10):
        expect(resume(pid), stdout="3\n3\n[1, 2, 3, 4, 5]\n")
"""

import os


def list_pids():
    return [int(pid) for pid in os.listdir("/proc") if pid.isdigit()]


print(os.readlink("/proc/self"), flush=True)
print(os.readlink("/proc/self"))
print(list_pids())
