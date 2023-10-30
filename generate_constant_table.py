import os
import re
import struct
import subprocess

CC = os.environ["CC"]


proc = subprocess.run(
    [CC, "-E", "-dM", "-"],
    input="""
#include <errno.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
""".encode(),
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
        if value[0] == "-" or value[0].isdigit() or value in defined_constants:
            if value[0] == "-":
                value = value.rstrip("ULE") + "isize"
            elif value[0].isdigit():
                value = value.rstrip("ULE") + "usize as isize"
            print(f"pub const {name}: isize = {value};")
            defined_constants.add(name)

        if name.startswith("SYS_"):
            print(f"pub const {name[4:]}: SyscallWrapper = SyscallWrapper({value});")
