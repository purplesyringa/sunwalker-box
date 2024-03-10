import json
import os
import re

ARCH = os.environ["ARCH"]
RESERVED = "const volatile void bool char signed unsigned short int long size_t".split()
SYSCALL_WRAPPER = 'Result<long> {name}({signature_args}) {{ return syscall({call_args}); }}'

INCLUDES = [
    "asm-generic/poll",
    "asm-generic/siginfo",
    "asm-generic/stat",
    "asm-generic/statfs",
    "asm-generic/types",
    "asm/signal",
    "linux/aio_abi",
    "linux/bpf",
    "linux/capability",
    "linux/eventpoll",
    "linux/fs",
    "linux/futex",
    "linux/futex",
    "linux/io_uring",
    "linux/kexec",
    "linux/landlock",
    "linux/mount",
    "linux/mqueue",
    "linux/msg",
    "linux/openat2",
    "linux/perf_event",
    "linux/posix_types",
    "linux/resource",
    "linux/rseq",
    "linux/sched",
    "linux/sched/types",
    "linux/sem",
    "linux/shm",
    "linux/stat",
    "linux/sysinfo",
    "linux/time",
    "linux/time_types",
    "linux/times",
    "linux/timex",
    "linux/uio",
    "linux/utime",
    "linux/utsname",
]

KERNEL_TYPES = "mode_t gid_t timer_t clockid_t loff_t fd_set pid_t mqd_t off_t uid_t key_t rwf_t".split()

TYPE_ALIASES = {
    'u32': '__u32',
    'umode_t': 'mode_t',
    'struct __aio_sigset': 'sigset_t',

    # see getcpu.2 -- unused since kernel 2.6.24
    'struct getcpu_cache': 'nullptr_t',

    # This is probably incorrect.
    'qid_t': 'long',

    # This is copyable; touch when really needed
    'struct file_handle': 'void',
    'struct sockaddr': 'void',
    'struct mmsghdr': 'void',

    # What about defines? No one cares
    'key_serial_t': 'int32_t',
}


def split_type(decl: str):
    decl = decl.replace('union ', '').replace('enum ', '').split()

    name = decl.pop()
    i = 0
    while i < len(name) and '*' == name[i]:
        i += 1
    stars, name = name[:i], name[i:]
    decl.append(stars)

    new_decl = []
    for d in decl:
        if False and d.isidentifier() and d not in RESERVED:
            NONTRIVIAL_DECLS.add(NONTRIVIAL_DECL.format(name=d))
            new_decl.append(f"::{d}")
        else:
            new_decl.append(d)

    sig_type = ' '.join(new_decl)

    for oldty, newty in TYPE_ALIASES.items():
        sig_type = re.sub(f"\\b{oldty}\\b", newty, sig_type)

    return sig_type, name


with open(f"generate/syscall_table_{ARCH}.json") as table:
    syscall_table = json.load(table)


SYSCALL_WRAPPERS = []

for syscall in syscall_table["syscalls"]:
    number: int = syscall["number"]
    name: str = syscall["name"]
    signature: list[str] = syscall["signature"]

    signature = list(map(split_type, signature))

    def into_declaration(sig):
        decltype, name = sig
        return f"{decltype} {name}"

    def into_value(sig):
        decltype, name = sig
        return f", (long){name}"

    SYSCALL_WRAPPERS.append(SYSCALL_WRAPPER.format(
        name=name,
        signature_args=', '.join(map(into_declaration, signature)),
        call_args=str(number) + ''.join(map(into_value, signature)),
    ))

for inc in INCLUDES:
    print(f"#include <{inc}.h>")
for ty in KERNEL_TYPES:
    print(f"#define {ty} __kernel_{ty}")
print("namespace libc {")
print('\n'.join(SYSCALL_WRAPPERS))
print("}")
