import os
import re
import struct
import subprocess

CC = os.environ["CC"]


# Find maximal suffix of s that is also a prefix of t
def overlap(s: str, t: str) -> int:
    for i in range(min(len(s), len(t)) + 1, 0, -1):
        if s[-i:] == t[:i]:
            return i
    return 0


def save_table(table_name: str, table: dict[str, int]):
    # Remove strings that are substrings of other strings
    names = sorted(table, key=lambda name: len(name))
    names = [name for i, name in enumerate(names) if not any(name in other for other in names[i + 1:])]

    # Find a short string containing all the names
    overlaps = [[overlap(s, t) for t in names] for s in names]
    while len(names) > 1:
        # Find a pair of strings with the largest overlap
        i, j = max(
            ((i, j) for i in range(len(names)) for j in range(len(names)) if i != j),
            key=lambda pair: overlaps[pair[0]][pair[1]]
        )
        common = overlaps[i][j]
        if common == 0:
            break
        new_name = names[i] + names[j][common:]

        # Remove strings that are substrings of the new string
        indices = [i for i, name in enumerate(names) if name not in new_name]
        overlaps = [[overlaps[i][j] for j in indices] for i in indices]
        names = [names[i] for i in indices]

        # Add the new name
        for i in range(len(names)):
            overlaps[i].append(overlap(names[i], new_name))
        overlaps.append([overlap(new_name, other) for other in names] + [len(new_name)])
        names.append(new_name)

    strings = "".join(names)

    # Build reference table
    ref_table = []
    for name, number in table.items():
        ref_table += [(0, 0)] * (number - len(ref_table) + 1)
        if ref_table[number] == (0, 0):
            ref_table[number] = (strings.index(name), len(name))

    max_offset = max(offset for offset, _ in ref_table)
    max_length = max(length for _, length in ref_table)

    assert (max_offset + 1) * (max_length + 1) <= 2 ** 16

    with open(f"target/{table_name}.info", "w") as f:
        f.write(repr((len(ref_table), max_length)))

    with open(f"target/{table_name}.offsets", "w") as f:
        f.write(repr([offset * (max_length + 1) + length for offset, length in ref_table]))

    with open(f"target/{table_name}.names", "w") as f:
        f.write(strings)


def extract_table_from_defines(file_name: str, name_prefix: str) -> dict[str, int]:
    # Determine macro names
    proc = subprocess.run(
        [CC, "-E", "-dM", "-"],
        input=f"#include <{file_name}>".encode(),
        check=True,
        capture_output=True
    )
    tails = []
    prefix = f"#define {name_prefix}"
    for line in proc.stdout.decode().splitlines():
        if line.startswith(prefix):
            tails.append(line[len(prefix):].split()[0])

    # Expand macros
    proc = subprocess.run(
        [CC, "-E", "-P", "-"],
        input=(
            f"#include <{file_name}>\n"
            + "".join(f"let {name_tail!r} = {name_prefix}{name_tail}\n" for name_tail in tails)
        ).encode(),
        check=True,
        capture_output=True
    )
    table = {}
    for line in proc.stdout.decode().splitlines():
        if line.startswith("let "):
            _, name, _, number = line.split(None, 3)
            table[eval(name)] = int(number)
    return table


def save_table_from_defines(table_name: str, file_name: str, name_prefix: str):
    save_table(table_name, extract_table_from_defines(file_name, name_prefix))


def save_syscall_table():
    save_table_from_defines("syscall_table", "sys/syscall.h", "__NR_")

def save_errno_table():
    save_table_from_defines("errno_table", "errno.h", "E")


save_syscall_table()
save_errno_table()
