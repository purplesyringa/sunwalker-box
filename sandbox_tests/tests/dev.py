"""
description: /dev has no unsafe mounts
"""

import os


ALLOWED_NAMES = {
    "shm", "ptmx", "pts", "mqueue", "fd", "stderr", "stdout", "stdin",
    "random", "urandom", "zero", "full", "null", "tty"
}


for name in os.listdir("/dev"):
    assert name in ALLOWED_NAMES, f"Unexpected file /dev/{name}"
