"""
description: lo is the only interface and is down
expect:
  stdout: |
    1: lo: <LOOPBACK> mtu 65536 qdisc noop state DOWN mode DEFAULT group default qlen 1000
        link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
"""

import os

os.system("ip link")
