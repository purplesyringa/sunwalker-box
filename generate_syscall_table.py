import os
import re
import struct
import subprocess

CC = os.environ["CC"]


proc = subprocess.run(
    [CC, "-E", "-dM", "-"],
    input="""
#define _GNU_SOURCE
#include <sys/syscall.h>
""".encode(),
    check=True,
    capture_output=True
)

regex = re.compile(r"#define SYS_(\w+) (\w+)")

for line in proc.stdout.decode().splitlines():
    match = regex.match(line)
    if match:
        name, value = match.groups()
        print(f"template<typename... Args> __attribute__((always_inline)) inline Result<long> {name}(Args... args) {{ return syscall({value}, (long)args...); }}")
