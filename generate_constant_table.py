import os
import re
import struct
import subprocess

CC = os.environ["CC"]


proc = subprocess.run(
    [CC, "-E", "-dM", "-"],
    input="#include <errno.h>\n#include <fcntl.h>\n#include <sys/syscall.h>\n".encode(),
    check=True,
    capture_output=True
)

const_regex = re.compile(r"#define (\w+) (\w+)")

defined_constants = set()

print("#![allow(dead_code, non_upper_case_globals)]")
print("use crate::syscall_wrapper::SyscallWrapper;")

for line in proc.stdout.decode().splitlines():
    match = const_regex.match(line)
    if match:
        name, value = match.groups()
        if value.isdigit() or value in defined_constants:
            print(f"pub const {name}: isize = {value};")
            defined_constants.add(name)

        if name.startswith("SYS_"):
            print(f"pub const {name[4:]}: SyscallWrapper = SyscallWrapper({value});")
