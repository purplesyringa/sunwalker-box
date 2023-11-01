import os
import re
import struct
import subprocess

CC = os.environ["CC"]


proc = subprocess.run(
    [CC, "-E", "-dM", "-"],
    input="""
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
""".encode(),
    check=True,
    capture_output=True
)

const_regex = re.compile(r"#define (\w+) (\w+)")

defined_constants = set()

print("#![allow(dead_code, non_upper_case_globals)]")
print("use crate::syscall_wrapper::SyscallWrapper;")

def normalize_int(s):
    s = s.rstrip("ULE")
    if s.startswith("0") and not s.startswith("0x"):
        s = f"0o{s}"
    return s

for line in proc.stdout.decode().splitlines():
    match = const_regex.match(line)
    if match:
        name, value = match.groups()
        if value[0] == "-" or value[0].isdigit() or value in defined_constants:
            if value[0] == "-":
                value = normalize_int(value) + "isize"
            elif value[0].isdigit():
                value = normalize_int(value) + "usize as isize"
            print(f"pub const {name}: isize = {value};")
            defined_constants.add(name)

        if name.startswith("SYS_"):
            print(f"pub const {name[4:]}: SyscallWrapper = SyscallWrapper({value});")
