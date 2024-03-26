import json
import os
import re

ARCH = os.environ["ARCH"]
SYSCALL_WRAPPER = "Result<long> {name}({signature_args}) {{ return syscall({call_args}); }}"

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
    "u32": "__u32",
    "umode_t": "mode_t",
    "struct __aio_sigset": "sigset_t",

    # see getcpu.2 -- unused since kernel 2.6.24
    "struct getcpu_cache": "std::nullptr_t",

    "qid_t": "uint32_t",

    # This is copyable; touch when really needed
    "struct file_handle": "void",
    "struct sockaddr": "void",
    "struct mmsghdr": "void",

    # What about defines? No one cares
    "key_serial_t": "int32_t",
}


def split_type(decl: str):
    match = re.fullmatch(r"(.*?)(\w+)", decl)
    sig_type = match[1]
    name = match[2]
    sig_type = re.sub(r"\w+", lambda match: TYPE_ALIASES.get(match[0], match[0]), sig_type)
    return sig_type, name


with open(f"generate/syscall_table_{ARCH}.json") as table:
    syscall_table = json.load(table)


SYSCALL_WRAPPERS = []

for syscall in syscall_table["syscalls"]:
    number: int = syscall["number"]
    name: str = syscall["name"]
    signature: list[str] = syscall["signature"]

    parsed_signature: list[tuple[str, str]] = list(map(split_type, signature))

    SYSCALL_WRAPPERS.append(SYSCALL_WRAPPER.format(
        name=name,
        signature_args=", ".join(f"{decltype} {name}" for decltype, name in parsed_signature),
        call_args=str(number) + "".join(f", (long){name}" for _, name in parsed_signature),
    ))

for inc in INCLUDES:
    print(f"#include <{inc}.h>")
for ty in KERNEL_TYPES:
    print(f"#define {ty} __kernel_{ty}")
print("namespace libc {")
print("\n".join(SYSCALL_WRAPPERS))
print("}")
