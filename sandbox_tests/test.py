#!/usr/bin/env python3
import abc
import contextlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
import time
import traceback
from typing import Callable, Optional
import yaml


CORE = 1

DEFAULT_ENV = {
    "LD_LIBRARY_PATH": "/usr/local/lib64:/usr/local/lib:/usr/lib64:/usr/lib:/lib64:/lib",
    "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    "LANGUAGE": "en_US",
    "LC_ALL": "en_US.UTF-8",
    "LC_ADDRESS": "en_US.UTF-8",
    "LC_NAME": "en_US.UTF-8",
    "LC_MONETARY": "en_US.UTF-8",
    "LC_PAPER": "en_US.UTF-8",
    "LC_IDENTIFIER": "en_US.UTF-8",
    "LC_TELEPHONE": "en_US.UTF-8",
    "LC_MEASUREMENT": "en_US.UTF-8",
    "LC_TIME": "en_US.UTF-8",
    "LC_NUMERIC": "en_US.UTF-8",
    "LANG": "en_US.UTF-8"
}


sunwalker_prefix = []


def parse_size(s: str) -> int:
    if " " not in s.strip():
        return int(s)
    value, unit = s.split()
    return int(float(value) * {
        "B": 1,
        "KB": 1000,
        "MB": 1000 ** 2,
        "GB": 1000 ** 3,
        "TB": 1000 ** 4,
        "PB": 1000 ** 5,
        "EB": 1000 ** 6,
        "ZB": 1000 ** 7,
        "YB": 1000 ** 8,
        "RB": 1000 ** 9,
        "QB": 1000 ** 10,
        "KiB": 1024,
        "MiB": 1024 ** 2,
        "GiB": 1024 ** 3,
        "TiB": 1024 ** 4,
        "PiB": 1024 ** 5,
        "EiB": 1024 ** 6,
        "ZiB": 1024 ** 7,
        "YiB": 1024 ** 8,
        "RiB": 1024 ** 9,
        "QiB": 1024 ** 10,
    }[unit])


def parse_approximate_value(s: str, value_parser: Callable[[str], float]) -> tuple[float, float]:
    value, error = s.split("+-")
    value = value_parser(value)
    if error.endswith("%"):
        percentage = float(error[:-1])
        error = percentage * value
    else:
        error = value_parser(error)
    return (value - error, value + error)


class Box:
    def __init__(self, opts: list[str] = []):
        self.proc = subprocess.Popen(sunwalker_prefix + ["../sunwalker_box", "start", "--core", str(
            CORE), *opts], stdin=subprocess.PIPE, stdout=subprocess.PIPE)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.proc.stdin.close()
        with self.proc:
            pass

    def cmd(self, name: str, arg=None):
        self.proc.stdin.write(f"{name} {json.dumps(arg)}\n".encode())
        self.proc.stdin.flush()
        line = self.proc.stdout.readline().strip().decode()
        if line == "ok":
            return None
        elif line.startswith("ok "):
            return json.loads(line[3:])
        elif line.startswith("error "):
            raise RuntimeError(json.loads(line[6:]))
        else:
            raise ValueError("Unexpected response from the box")

    def mkdir(self, path: str):
        return self.cmd("mkdir", path)

    def ls(self, path: str) -> dict[str, ...]:
        return self.cmd("ls", path)

    def cat(self, path: str, at: int = 0, len: int = 0) -> bytes:
        return bytes(self.cmd("cat", {"path": path, "at": at, "len": len}))

    def mkfile(self, path: str, content: bytes = b""):
        return self.cmd("mkfile", {"path": path, "content": list(content)})

    def mksymlink(self, target: str, link: str):
        return self.cmd("mksymlink", {"target": target, "link": link})

    def bind(self, source: str, mountpoint: str, readonly: bool = False):
        return self.cmd("bind", {"external": source, "internal": mountpoint, "ro": readonly})

    def reset(self):
        return self.cmd("reset")

    def commit(self):
        return self.cmd("commit")

    def run(
        self,
        argv: list[str],
        stdin: Optional[str] = None,
        stdout: Optional[str] = None,
        stderr: Optional[str] = None,
        real_time_limit: Optional[float] = None,
        cpu_time_limit: Optional[float] = None,
        idleness_time_limit: Optional[float] = None,
        memory_limit: Optional[int] = None,
        processes_limit: Optional[int] = None,
        env: dict[str, str] = None
    ) -> dict[str, ...]:
        return self.cmd("run", {
            "argv": argv,
            "stdin": stdin,
            "stdout": stdout,
            "stderr": stderr,
            "real_time_limit": real_time_limit,
            "cpu_time_limit": cpu_time_limit,
            "idleness_time_limit": idleness_time_limit,
            "memory_limit": memory_limit,
            "processes_limit": processes_limit,
            "env": env
        })


class Test(abc.ABC):
    slug: str
    description: str
    arch: list[str]

    def prepare(self, tester):
        pass

    @abc.abstractmethod
    def run(self):
        ...


def create_dirs(structure: dict[str, ...], dir: str):
    for name, value in structure.items():
        path = os.path.join(dir, name)
        if isinstance(value, dict):
            os.mkdir(path)
            create_dirs(value, path)
        elif isinstance(value, str):
            if value.startswith("-> "):
                os.symlink(value[3:], path)
            else:
                with open(path, "wb") as f:
                    f.write(value.encode())
        else:
            assert False, value

        os.lchown(path, 2, 2)  # internal user


class SimpleTest(Test):
    def __init__(
        self,
        slug: str,
        description: str,
        arch: Optional[list[str]] = None,
        runs: int = 1,
        pass_run_number: bool = False,
        assets: dict[str, str] = {},
        root: Optional[dict[str, ...]] = None,
        preexec: list[str] = [],
        static: bool = False,
        outer_env: dict[str, str] = {},
        env: dict[str, str] = DEFAULT_ENV,
        quotas: dict[str, ...] = {},
        input: Optional[str] = None,
        expect: dict[str, ...] = {},
        limits: dict[str, ...] = {}
    ):
        self.slug = slug
        self.description = description
        self.arch = arch
        self.runs = runs
        self.pass_run_number = pass_run_number
        self.assets = assets
        self.root = root
        self.preexec = preexec
        self.static = static
        self.outer_env = outer_env
        self.env = env
        self.quotas = quotas
        self.input = input
        self.expect = expect
        self.limits = limits
        self.root_dir = None
        self.files_committed = False

    def prepare(self, tester):
        if self.root is not None:
            self.root_dir = f"build/roots/{self.slug}"
            if os.path.isdir(self.root_dir):
                shutil.rmtree(self.root_dir)
            os.mkdir(self.root_dir)

            create_dirs(self.root, self.root_dir)

        if self.assets:
            self.assets_dir = f"build/assets/{self.slug}"
            if os.path.isdir(self.assets_dir):
                shutil.rmtree(self.assets_dir)
            os.mkdir(self.assets_dir)

            create_dirs(self.assets, self.assets_dir)

    @abc.abstractmethod
    def _bind_and_run(self, box, argv: list[str], **kwargs):
        ...

    def run(self, tester):
        opts = []
        if "space" in self.quotas:
            opts += ["--quota-space", str(self.quotas["space"])]
        if "inodes" in self.quotas:
            opts += ["--quota-inodes", str(self.quotas["inodes"])]
        for key, value in self.outer_env.items():
            os.environ[key] = value
        if self.root is not None:
            opts += ["--root", self.root_dir]

        with Box(opts) as box:
            previous_values = {}

            for i in range(self.runs):
                try:
                    if i != 0:
                        box.reset()

                    if self.input is None:
                        stdin = None
                    else:
                        stdin = "/space/stdin.txt"
                        box.mkfile("/space/stdin.txt", self.input.encode())

                    should_commit = False
                    for cmd in self.preexec:
                        args = cmd.split()
                        if args[0].startswith("~"):
                            runs = list(map(int, args[0][1:].split(",")))
                            if i not in runs:
                                continue
                            args.pop(0)
                        cmd = args.pop(0)
                        if cmd == "mkdir":
                            for arg in args:
                                box.mkdir(arg)
                        elif cmd == "touch":
                            for arg in args:
                                box.mkfile(arg)
                        elif cmd == "bind":
                            readonly = False
                            if args[0] == "-ro":
                                readonly = True
                                args.pop(0)
                            if len(args) != 2:
                                raise ValueError("Invalid bind syntax")
                            source, target = args
                            if source.startswith("@"):
                                source = os.path.abspath(
                                    self.assets_dir + "/" + source[1:])
                            box.bind(source, target, readonly=readonly)
                        elif cmd == "commit":
                            should_commit = True
                        else:
                            raise ValueError(f"Unknown command {cmd}")

                    limits = {}
                    for (key, parser) in [
                        ("cpu_time", float),
                        ("idleness_time", float),
                        ("real_time", float),
                        ("memory", parse_size),
                        ("processes", int)
                    ]:
                        if key in self.limits:
                            limits[f"{key}_limit"] = parser(self.limits[key])

                    argv = []
                    if self.pass_run_number:
                        argv.append(str(i))

                    result = self._bind_and_run(
                        box,
                        argv,
                        stdin=stdin,
                        stdout="/space/stdout.txt",
                        stderr="/space/stderr.txt",
                        env=self.env,
                        **limits
                    )

                    for key, default_value in [
                        ("limit_verdict", "OK"),
                        ("exit_code", 0 if result["limit_verdict"] == "OK" else -1)
                    ]:
                        value = result[key]
                        expected_value = self.expect.get(key, default_value)
                        if expected_value is not None:
                            stdout = box.cat("/space/stdout.txt").decode()
                            stderr = box.cat("/space/stderr.txt").decode()
                            assert value == expected_value, f"Expected {key}: {expected_value}, actual: {value}\n\nstdout:\n{stdout}\nstderr:\n{stderr}"

                    for key in ("stdout", "stderr"):
                        value = box.cat(f"/space/{key}.txt")

                        patched_value = value
                        if self.expect.get(f"unordered_{key}"):
                            patched_value = b"\n".join(
                                sorted(patched_value.split(b"\n")))

                        if key in self.expect:
                            expected_value = self.expect[key].encode()
                            patched_expected_value = expected_value
                            if self.expect.get(f"unordered_{key}"):
                                patched_expected_value = b"\n".join(
                                    sorted(patched_expected_value.split(b"\n")))
                            assert patched_value == patched_expected_value, f"Expected {key}: {expected_value}, actual: {value}"

                        matching = self.expect.get(f"matching_{key}")
                        if matching:
                            if i == 0:
                                previous_values[key] = (value, patched_value)
                            else:
                                previous_value, patched_previous_value = previous_values[key]

                                err_text = f"Expected {key} to match the value from the first run: {previous_value}, actual: {value}"
                                if matching is True:
                                    assert patched_value == patched_previous_value, err_text
                                elif matching.startswith("+-"):
                                    previous_values = patched_previous_value.decode().split()
                                    new_values = patched_value.decode().split()

                                    assert len(previous_values) == len(
                                        new_values), f"Different lengths of values: current: {new_values}, previous: {previous_values}"

                                    for prev, new in zip(previous_values, new_values):
                                        l, r = parse_approximate_value(
                                            prev + matching, float)
                                        assert l <= float(new) <= r, err_text
                                else:
                                    assert False, f"Invalid matching value: {matching}"

                    for (key, parser) in [
                        ("cpu_time", float),
                        ("idleness_time", float),
                        ("real_time", float),
                        ("memory", parse_size)
                    ]:
                        value = result[key]
                        if key in self.expect:
                            expected_value = self.expect[key]
                            l, r = parse_approximate_value(expected_value, parser)
                            assert l <= value <= r, f"Expected {key}: {expected_value}, actual: {value}\n\nstdout:\n{stdout}\nstderr:\n{stderr}"

                    if should_commit:
                        box.commit()
                        self.files_committed = True
                except AssertionError as e:
                    if self.runs > 1:
                        raise AssertionError(f"Run {i}: {e}") from None
                    else:
                        raise



class CTest(SimpleTest):
    def prepare(self, tester):
        cc = "gcc"
        ccflags = ""

        if self.static:
            cc = "musl-gcc"
            ccflags += " -static"

        tester.f_makefile.write(
            f"{self.slug}: ../tests/{self.slug}.c\n\t{cc} $^ -o $@{ccflags}\n\n")
        tester.make_targets.append(f"{self.slug}")

        super().prepare(tester)

    def _bind_and_run(self, box, argv: list[str], **kwargs):
        if not self.files_committed:
            box.mkfile(f"/space/{self.slug}")
            box.bind(os.path.abspath(
                f"build/{self.slug}"), f"/space/{self.slug}", readonly=True)
        return box.run([f"/space/{self.slug}"] + argv, **kwargs)


class PyTest(SimpleTest):
    def _bind_and_run(self, box, argv: list[str], **kwargs):
        if not self.files_committed:
            box.mkfile(f"/space/{self.slug}.py")
            box.bind(os.path.abspath(
                f"tests/{self.slug}.py"), f"/space/{self.slug}.py", readonly=True)
        return box.run(["/usr/bin/python3", f"/space/{self.slug}.py"] + argv, **kwargs)


class Tester:
    def __init__(self, f_makefile: io.TextIOBase, arch: str):
        self.f_makefile = f_makefile
        self.arch = arch
        self.make_targets: list[str] = []
        self.tests: list[Test] = []

    def register_c_test(self, source_path: str):
        with open(source_path) as f:
            yaml_header = re.match(r"/\*([\s\S]+?)\*/", f.read()).group(1)
        header = yaml.unsafe_load(yaml_header)

        slug = os.path.basename(source_path).removesuffix(".c")

        self.tests.append(CTest(slug, **header))

    def register_py_test(self, source_path: str):
        with open(source_path) as f:
            yaml_header = re.match(
                r"\"\"\"([\s\S]+?)\"\"\"", f.read()).group(1)
        header = yaml.unsafe_load(yaml_header)

        slug = os.path.basename(source_path).removesuffix(".py")

        self.tests.append(PyTest(slug, **header))

    def prepare(self):
        for test in self.tests:
            if test.arch is not None and self.arch not in test.arch:
                continue
            test.prepare(self)

        self.f_makefile.write("all: " + " ".join(self.make_targets))
        self.f_makefile.close()

        subprocess.run(["make", "-C", "build", "all"], check=True)

    def run(self):
        passes = 0
        skips = 0
        failures = 0
        crashes = 0

        for test in self.tests:
            if test.arch is not None and self.arch not in test.arch:
                skips += 1
                print(f"     \x1b[93mSKIP\x1b[0m [{test.slug}]", flush=True)
                continue

            print(f"          [{test.slug}]", end="", flush=True)

            buf_stdout = io.StringIO()

            start_time = time.time()
            try:
                with contextlib.redirect_stdout(buf_stdout):
                    test.run(self)
            except Exception as e:
                ex = e, traceback.format_exc()
            else:
                ex = None
            end_time = time.time()

            duration = end_time - start_time

            if duration > 0.1:
                time_text = f"{duration:.1f}s"
            else:
                time_text = " " * 4
            print(f"\r\x1b[36m{time_text}\x1b[0m ", end="")

            if ex:
                print("\x1b[91mFAIL\x1b[0m")
                print("\x1b[36m  " + test.description + "\x1b[0m")
                buf_stdout.seek(0)
                print("  " + buf_stdout.read().rstrip("\n").replace("\n", "\n  "))
                if isinstance(ex[0], AssertionError):
                    print("\x1b[33m  " +
                          str(ex[0]).replace("\n", "\n  ") + "\x1b[0m")
                    failures += 1
                else:
                    print("\x1b[95m" + ex[1] + "\x1b[0m")
                    crashes += 1
            else:
                print("\x1b[32m OK\x1b[0m")
                passes += 1

        print("  ".join(
            pattern
            .replace("{}", str(cnt))
            .replace("{s}", "" if cnt == 1 else "s")
            for pattern, cnt in
            [
                ("\x1b[32m{} test{s} passed\x1b[0m", passes),
                ("\x1b[93m{} test{s} skipped\x1b[0m", skips),
                ("\x1b[91m{} test{s} failed\x1b[0m", failures),
                ("\x1b[95m{} test{s} crashed\x1b[0m", crashes)
            ]
            if cnt > 0
        ))
        if failures > 0 or crashes > 0:
            raise SystemExit(1)


def main():
    global sunwalker_prefix

    os.makedirs("build", exist_ok=True)
    os.makedirs("build/roots", exist_ok=True)
    os.makedirs("build/assets", exist_ok=True)
    f_makefile = open("build/Makefile", "w")

    # sunwalker_prefix = ["strace", "-f"]

    subprocess.run(["../sunwalker_box", "isolate",
                   "--core", str(CORE)], check=True)

    try:
        tester = Tester(f_makefile, sys.argv[1])

        # with Box() as box:
            # box.commit()
            # for _ in range(1000):
                # box.reset()
                # box.run(["/usr/bin/python3", "-c", ""])
        # box.mkfile("/space/cat")
        # box.mkfile("/space/stdin", b"Hello, world!")
        # box.bind("/usr/bin/cat", "/space/cat", readonly=True)
        # box.run(["/space/cat"], stdin="/space/stdin",
        #         stdout="/space/stdout")
        # box.cat("/space/stdout")

        for test_file in sorted(os.listdir("tests")):
            if test_file.endswith(".c"):
                tester.register_c_test(os.path.join("tests", test_file))
            elif test_file.endswith(".py"):
                tester.register_py_test(os.path.join("tests", test_file))

        tester.prepare()
        tester.run()
    finally:
        subprocess.run(["../sunwalker_box", "free",
                       "--core", str(CORE)], check=True)


if __name__ == "__main__":
    main()
