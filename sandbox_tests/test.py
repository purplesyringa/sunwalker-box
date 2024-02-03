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
        "KiB": 1024,
        "MiB": 1024 ** 2,
        "GiB": 1024 ** 3,
        "TiB": 1024 ** 4,
        "PiB": 1024 ** 5,
        "EiB": 1024 ** 6,
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
        self.proc = subprocess.Popen(
            ["../sunwalker_box", "start", "--core", str(CORE), *opts],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE
        )

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


def contextify(text: str, context: Optional[...] = None) -> str:
    return f"{context}: {text}" if context else text


def expect_output(key, value, previous_values, expect, context):
    patched_value = value
    if expect.get(f"unordered_{key}"):
        patched_value = b"\n".join(sorted(patched_value.split(b"\n")))

    if key in expect:
        expected_value = expect[key].encode()
        patched_expected_value = expected_value
        if expect.get(f"unordered_{key}"):
            patched_expected_value = b"\n".join(sorted(patched_expected_value.split(b"\n")))
        assert patched_value == patched_expected_value, contextify(f"Expected {key}: {expected_value}, actual: {value}", context)

    matching = expect.get(f"matching_{key}")
    if matching:
        if not previous_values:
            previous_values[key] = (value, patched_value)
            return previous_values

        previous_value, patched_previous_value = previous_values[key]

        err_text = contextify(f"Expected {key} to match the value from the first run: {previous_value}, actual: {value}", context)
        if matching is True:
            assert patched_value == patched_previous_value, err_text
        elif matching.startswith("+-"):
            previous_values = patched_previous_value.decode().split()
            new_values = patched_value.decode().split()

            assert len(previous_values) == len(new_values), contextify(
                f"Different lengths of values: current: {new_values}, previous: {previous_values}", context)

            for prev, new in zip(previous_values, new_values):
                l, r = parse_approximate_value(prev + matching, float)
                assert l <= float(new) <= r, err_text
        else:
            assert False, contextify(f"Invalid matching value: {matching}", context)
    return previous_values


def expect(result, previous_values={}, **expect):
    box, context, stdout_path, stderr_path, result = result

    pretty_result = json.dumps(result, indent=2)

    stdout = box.cat(stdout_path).decode() if stdout_path else ''
    stderr = box.cat(stderr_path).decode() if stderr_path else ''

    def expect_key(key, result, expected):
        assert result == expected, contextify(f"Expected {key}: {expected}, actual: {result}\n\nstdout:\n{stdout}\nstderr:\n{stderr}", context)

    limit_verdict = expect.get("limit_verdict", "OK")
    expect_key("verdict", result["limit_verdict"], limit_verdict)
    expect_key("exit code", result["exit_code"], expect.get("exit_code", 0 if limit_verdict == "OK" else -1))

    if stdout_path:
        previous_values = expect_output("stdout", stdout.encode(), previous_values, expect, context)
    if stderr_path:
        previous_values = expect_output("stderr", stderr.encode(), previous_values, expect, context)

    for (key, parser) in [
        ("cpu_time", float),
        ("idleness_time", float),
        ("real_time", float),
        ("memory", parse_size)
    ]:
        value = result[key]
        if key in expect:
            expected_value = expect[key]
            l, r = parse_approximate_value(expected_value, parser)
            assert l <= value <= r, contextify(
                f"Expected {key}: {expected_value}, actual: {value}\n\nstdout:\n{stdout}\nstderr:\n{stderr}", context)

    return (context, result, previous_values)


class SimpleTest(Test):
    def __init__(
        self,
        slug: str,
        description: str,
        arch: Optional[list[str]] = None,
        assets: dict[str, str] = {},
        root: Optional[dict[str, ...]] = None,
        static: bool = False,
        outer_env: dict[str, str] = {},
        quotas: dict[str, ...] = {},
        script: Optional[str] = None,
    ):
        self.slug = slug
        self.description = description
        self.arch = arch
        self.assets = assets
        self.root = root
        self.static = static
        self.outer_env = outer_env
        self.quotas = quotas
        self.script = script
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
    def _bind(self, box):
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

        if self.script is None:
            # return self.legacy_run(tester, opts)
            assert False, "Non-script tests are unsupported"

        with Box(opts) as box:

            def run(context=None, exe=None, argv=None, input=None, stdin=None, stdout=None, stderr=None, env=None, **limits):
                try:
                    if input is None:
                        stdin = None
                    else:
                        stdin = stdin or "/space/stdin.txt"
                        box.mkfile(stdin, input.encode())

                    stdout = stdout or "/space/stdout.txt"
                    stderr = stderr or "/space/stderr.txt"

                    return (box, context, stdout, stderr, box.run(
                        ([exe] if exe else self.argv) + (argv or []),
                        env=env or DEFAULT_ENV,
                        stdin=stdin,
                        stdout=stdout,
                        stderr=stderr,
                        **limits
                    ))
                except AssertionError as e:
                    assert False, contextify(e, context)
                except Exception as e:
                    if context:
                        e.add_note(f"Context: {context}")
                    raise e

            def bind(source, destination, readonly=False, asset=True):
                return box.bind(os.path.abspath(f"{self.assets_dir}/{source}") if asset else source, destination, readonly)

            def bind_ro(source, destination, asset=True):
                return bind(source, destination, True, asset)

            def commit():
                self.files_committed = True
                return box.commit()

            def run_reset():
                box.reset()
                self._bind(box)

            aliases = {
                "mkdir": box.mkdir,
                "ls": box.ls,
                "cat": box.cat,
                "touch": box.mkfile,
                "into": box.mkfile,
                "link": box.mksymlink,
                "reset": box.reset,
            }

            try:
                self._bind(box)
                exec(self.script, aliases | locals() | globals())
            except Exception as e:
                error_line = -1
                if e.__traceback__.tb_next:
                    error_line = e.__traceback__.tb_next.tb_lineno
                if isinstance(e, SyntaxError):
                    error_line = e.lineno

                arrow, blue, reset = '\x1b[91m->', '\x1b[34m', '\x1b[0m'
                script = '\n'.join(
                    f"  {arrow if i == error_line else '  '}{blue}{i:2}{reset}  {line}"
                    for i, line
                    in enumerate(self.script.split('\n')[:-1], 1)
                )
                print(f"Executed script:\n{script}")
                raise


class CTest(SimpleTest):
    def prepare(self, tester):
        ccflags = " -static" if self.static else ""

        try:
            _gcc = subprocess.run(["gcc", "-v"], capture_output=True, text=True).stderr
        except:
            _gcc = ""

        try:
            _musl_gcc = subprocess.run(["musl-gcc", "-v"], capture_output=True, text=True).stderr
        except:
            _musl_gcc = ""

        if "musl" in _gcc:
            cc = "gcc"
        elif "musl" in _musl_gcc:
            cc = "musl-gcc"
        else:
            assert False, "You need a working musl gcc (gcc or musl-gcc binary in PATH) to run C tests"

        tester.f_makefile.write(f"{self.slug}: ../tests/{self.slug}.c\n\t{cc} $^ -o $@{ccflags}\n\n")
        tester.make_targets.append(f"{self.slug}")

        super().prepare(tester)

    def _bind(self, box):
        if self.files_committed:
            return

        self.path = f"/space/{self.slug}"
        self.argv = [self.path]
        box.mkfile(self.path)
        box.bind(os.path.abspath(f"build/{self.slug}"), self.path, readonly=True)


class PyTest(SimpleTest):
    def _bind(self, box):
        if self.files_committed:
            return

        self.path = f"/space/{self.slug}.py"
        self.argv = ["/usr/bin/python3", self.path]
        box.mkfile(self.path)
        box.bind(os.path.abspath(f"tests/{self.slug}.py"), self.path, readonly=True)


class YamlTest(SimpleTest):
    def _bind(self, box):
        pass


class Tester:
    def __init__(self, f_makefile: io.TextIOBase, arch: str, test_whitelist: Optional[list[str]] = None):
        self.f_makefile = f_makefile
        self.arch = arch
        self.test_whitelist = test_whitelist
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
            yaml_header = re.match(r"\"\"\"([\s\S]+?)\"\"\"", f.read()).group(1)
        header = yaml.unsafe_load(yaml_header)

        slug = os.path.basename(source_path).removesuffix(".py")

        self.tests.append(PyTest(slug, **header))

    def register_yaml_test(self, source_path: str):
        with open(source_path) as f:
            yaml_header = f.read()
        header = yaml.unsafe_load(yaml_header)

        slug = os.path.basename(source_path).removesuffix(".yaml")

        self.tests.append(YamlTest(slug, **header))

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
            if (
                (test.arch is not None and self.arch not in test.arch)
                or (self.test_whitelist and test.slug not in self.test_whitelist)
            ):
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
                    print("\x1b[33m  " + str(ex[0]).replace("\n", "\n  ") + "\x1b[0m")
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
    os.makedirs("build", exist_ok=True)
    os.makedirs("build/roots", exist_ok=True)
    os.makedirs("build/assets", exist_ok=True)
    f_makefile = open("build/Makefile", "w")

    subprocess.run(["../sunwalker_box", "isolate", "--core", str(CORE)], check=True)

    try:
        if len(sys.argv) >= 3:
            test_whitelist = sys.argv[2].split(",")
        else:
            test_whitelist = None

        tester = Tester(f_makefile, sys.argv[1], test_whitelist)

        # with Box() as box:
        #    box.commit()
        #    for _ in range(1000):
        #        box.reset()
        #        box.run(["/usr/bin/python3", "-c", ""])
        # box.mkfile("/space/cat")
        # box.mkfile("/space/stdin", b"Hello, world!")
        # box.bind("/usr/bin/cat", "/space/cat", readonly=True)
        # box.run(["/space/cat"], stdin="/space/stdin",
        #         stdout="/space/stdout")
        # box.cat("/space/stdout")

        for test_file in sorted(os.listdir("tests")):
            name = test_file.partition(".")[0]
            path = os.path.join("tests", test_file)
            if test_file.endswith(".c"):
                tester.register_c_test(path)
            elif test_file.endswith(".py"):
                tester.register_py_test(path)
            elif test_file.endswith(".yaml"):
                tester.register_yaml_test(path)

        tester.prepare()
        tester.run()
    finally:
        subprocess.run(["../sunwalker_box", "free", "--core", str(CORE)], check=True)


if __name__ == "__main__":
    main()
