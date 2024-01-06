import json
import sys

json.dump(sys.stdin.read()[:-1].split("\x00"), sys.stdout)
