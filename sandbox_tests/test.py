#!/usr/bin/env python3
import argparse
from concurrent.futures import ThreadPoolExecutor
import dataclasses
import io
import json
import os
import re
import shutil
import subprocess
import sys
import time
import threading
import traceback
import queue
from typing import Optional
import yaml

import sunwalker_box
from tester_box import Box


@dataclasses.dataclass
class Test:
    slug: str
    static: Optional[bool] = None
    assets: Optional[dict[str, str]] = None
    root: Optional[dict[str, ...]] = None

    def __post_init__(self):
        self.root_dir = None
        self.assets_dir = None
        self.files_committed = False
        self.argv = []

    def _create_dirs(self, structure: dict[str, ...], dir: str):
        for name, value in structure.items():
            path = os.path.join(dir, name)
            if isinstance(value, dict):
                os.mkdir(path)
                self._create_dirs(value, path)
            elif isinstance(value, str):
                if value.startswith("-> "):
                    os.symlink(value[3:], path)
                else:
                    with open(path, "wb") as f:
                        f.write(value.encode())
            else:
                assert False, value

            os.lchown(path, 2, 2)  # internal user

    def prepare(self, tester):
        if self.root is not None:
            self.root_dir = f"build/roots/{self.slug}"
            if os.path.isdir(self.root_dir):
                shutil.rmtree(self.root_dir)
            os.mkdir(self.root_dir)

            self._create_dirs(self.root, self.root_dir)

        if self.assets is not None:
            self.assets_dir = f"build/assets/{self.slug}"
            if os.path.isdir(self.assets_dir):
                shutil.rmtree(self.assets_dir)
            os.mkdir(self.assets_dir)

            self._create_dirs(self.assets, self.assets_dir)

    def bind(self, box: Box):
        ...


class CTest(Test):
    def prepare(self, tester):
        ccflags = " -static" if self.static else ""

        try:
            _gcc = subprocess.run(["gcc", "-v"], capture_output=True, text=True).stderr
        except Exception:
            _gcc = ""

        try:
            _musl_gcc = subprocess.run(["musl-gcc", "-v"], capture_output=True, text=True).stderr
        except Exception:
            _musl_gcc = ""

        if "musl" in _gcc:
            cc = "gcc"
        elif "musl" in _musl_gcc:
            cc = "musl-gcc"
        else:
            assert False, "You need a working musl gcc (gcc or musl-gcc binary in PATH) to run C tests"

        tester.f_makefile.write(f"{self.slug}: ../tests/{self.slug}.c\n\t{cc} $^ -o $@{ccflags}\n\n")
        tester.make_targets.append(self.slug)

        super().prepare(tester)

    def bind(self, box: sunwalker_box.Box):
        if self.files_committed:
            return

        path = f"/space/{self.slug}"
        self.argv = [path]
        box.touch(path)
        box.bind(os.path.abspath(f"build/{self.slug}"), path, readonly=True)


class PyTest(Test):
    def bind(self, box: sunwalker_box.Box):
        if self.files_committed:
            return

        path = f"/space/{self.slug}.py"
        self.argv = ["/usr/bin/python3", path]
        box.touch(path)
        box.bind(os.path.abspath(f"tests/{self.slug}.py"), path, readonly=True)


class YamlTest(Test):
    pass


@dataclasses.dataclass
class SingleTest:
    slug: str
    description: str
    test: Test
    script: str
    arch: Optional[list[str]] = None
    outer_env: dict[str, str] = dataclasses.field(default_factory=lambda: {})
    quotas: dict[str, ...] = dataclasses.field(default_factory=lambda: {})
    slow: bool = False

    def __post_init__(self):
        if self.outer_env is None:
            self.outer_env = {}
        if self.quotas is None:
            self.quotas = {}

    def prepare(self, tester):
        self.test.prepare(tester)

    def run(self, box_config, core: int, error: queue.Queue):
        for key, value in self.outer_env.items():
            os.environ[key] = value

        with Box(
            box_config,
            sunwalker_box.Config(
                core=core,
                root=self.test.root_dir,
                quotas=sunwalker_box.Quota(
                    space=self.quotas.get("space"),
                    inodes=self.quotas.get("inodes")
                )
            )
        ) as box:

            def run(run=None, input=None, stdio=None, limits=None, context=None):
                return box.run(run or sunwalker_box.Run(argv=self.test.argv), input, stdio, limits, context)

            def bind(source, mountpoint, readonly=False):
                # This is a hack to use assets unless absolute path is explicitly used, because one should not rely on current workdir here
                if not os.path.isabs(source):
                    source = os.path.abspath(os.path.join(self.test.assets_dir, source))
                return box.bind(source, mountpoint, readonly)

            def bind_ro(source, mountpoint):
                return bind(source, mountpoint, readonly=True)

            def commit():
                self.test.files_committed = True
                return box.commit()

            def run_reset():
                box.reset()
                self.test.bind(box)

            touch = box.touch
            mkdir = box.mkdir
            mkfile = box.mkfile
            expect = box.expect
            extpath = box.extpath
            reset = box.reset

            try:
                self.test.bind(box)
                argv = self.test.argv

                header = "from sunwalker_box import *; from tester_box import *\n"
                exec(header + self.script, globals() | locals() | {"parse_size": None})

            except Exception as e:
                error_line = -1
                if e.__traceback__.tb_next:
                    error_line = e.__traceback__.tb_next.tb_lineno
                if isinstance(e, SyntaxError):
                    error_line = e.lineno

                arrow, blue, reset = '\x1b[91m->', '\x1b[34m', '\x1b[0m'
                script = '\n'.join(
                    f"  {arrow if i + 1 == error_line else '  '}{blue}{i:2}{reset}  {line}"
                    for i, line
                    in enumerate(self.script.split('\n')[:-1], 1)
                )
                error.put(f"Executed script:\n{script}")
                raise


@dataclasses.dataclass
class TestStarted:
    slug: str


@dataclasses.dataclass
class TestFinished:
    slug: str
    description: str
    duration: float
    ex: Exception
    trace: str
    error: queue.Queue

    def __post_init__(self):
        if not self.ex:
            self.kind = "pass"
        elif isinstance(self.ex, AssertionError):
            self.kind = "failure"
        else:
            self.kind = "crash"

    def as_strings(self):
        time_text = f"{self.duration:.1f}s" if self.duration > 0.1 else "    "
        yield f"\x1b[36m{time_text}\x1b[0m "

        status = "\x1b[32m OK \x1b[0m" if self.kind == "pass" else "\x1b[91mFAIL\x1b[0m"
        yield f'{status} {self.slug}'

        if self.kind != "pass":
            yield '\n'
            yield f"\x1b[36m  {self.description}\x1b[0m\n"

            while not self.error.empty():
                message = self.error.get_nowait()
                yield from ('  --- executor message ---\n  ', message.replace('\n', '\n  '), '\n')

            if self.kind == "failure":
                yield from ("\x1b[33m  ", str(self.ex).replace("\n", "\n  "), "\x1b[0m\n    ", '\n    '.join(self.ex.__notes__))
            elif self.kind == "crash":
                yield from ("\x1b[95m", self.ex, "\x1b[0m\n", self.trace)


class Testset:
    def __init__(self, len):
        self.current = set()
        self.count = 0
        self.len = len

    def started(self, slug):
        self.current.add(slug)

    def finished(self, slug):
        self.current.remove(slug)
        self.count += 1

    def is_running(self):
        return self.count != self.len

    def __str__(self):
        return f"[{self.count}/{self.len}] Testing {', '.join(self.current)}..."


@dataclasses.dataclass
class Tester:
    box_config: sunwalker_box.BoxConfig
    arch: str
    allow: Optional[set[str]] = None
    block: Optional[set[str]] = None
    hide_passed: bool = False
    bail_on_fail: bool = False
    current_status: bool = False

    def __post_init__(self):
        os.makedirs("build", exist_ok=True)

        self.f_makefile = open("build/Makefile", "w")
        self.make_targets: list[str] = []
        self.tests: list[SingleTest] = []
        self.skips = 0

        os.makedirs("build/roots", exist_ok=True)
        os.makedirs("build/assets", exist_ok=True)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, exc_traceback):
        pass

    def register(self):
        for test_file in os.listdir("tests"):
            slug, ext = test_file.rsplit(".", 1)
            if slug in (self.block or set()) or slug not in (self.allow or slug):
                self.skips += 1
                continue

            test_class: Test
            with open(os.path.join("tests", test_file)) as f:
                if ext == "c":
                    test_class, yaml_header = CTest, re.match(r"/\*([\s\S]+?)\*/", f.read()).group(1)
                elif ext == "py":
                    test_class, yaml_header = PyTest, re.match(r"\"\"\"([\s\S]+?)\"\"\"", f.read()).group(1)
                elif ext == "yaml":
                    test_class, yaml_header = YamlTest, f.read()

            header = yaml.unsafe_load(yaml_header)
            if self.arch not in (header.get("arch") or self.arch):
                self.skips += 1
                continue

            # I AM NORMAL I AM PERFECTLY SANE
            self.tests.append(SingleTest(
                slug,
                test=test_class(slug, **{key: header.get(key) for key in "static root assets".split()}),
                **{key: header.get(key) for key in "description script arch outer_env quotas slow".split()}
            ))

    def prepare(self):
        for test in self.tests:
            test.prepare(self)

        self.f_makefile.write("all: " + " ".join(self.make_targets))
        self.f_makefile.close()

        subprocess.run(["make", "-C", "build", "all"], check=True)

    def _run_single_test(self, box_config, test, cpus, feedback):
        try:
            feedback.put(TestStarted(test.slug))

            thread_name = threading.current_thread().name
            cpu_index = int(thread_name.rsplit('_', 1)[1])
            cpu = cpus[cpu_index]

            error = queue.Queue()

            start_time = time.time()
            try:
                test.run(box_config, cpu, error)
            except Exception as e:
                ex, trace = e, traceback.format_exc()
            else:
                ex, trace = None, None
            end_time = time.time()

            duration = end_time - start_time

        except BaseException as e:
            ex, trace, error, duraiton = e, traceback.format_exc(), queue.Queue(), locals().get('duration', 0)

        feedback.put(TestFinished(test.slug, test.description, duration, ex, trace, error))

    def run(self, cpus):
        passes = 0
        failures = 0
        crashes = 0

        feedback = queue.Queue()

        executor = ThreadPoolExecutor(max_workers=len(cpus), thread_name_prefix='invoker')
        for test in sorted(self.tests, key=lambda test: not test.slow):
            executor.submit(self._run_single_test, self.box_config, test, cpus, feedback)

        current = Testset(len(self.tests))
        while current.is_running():
            if self.current_status == 'show':
                print(f'\r\x1b[K{current}', flush=True, end='')

            try:
                event = feedback.get()
            except KeyboardInterrupt:
                print()
                break

            if type(event) is TestStarted:
                current.started(event.slug)

            elif type(event) is TestFinished:
                current.finished(event.slug)

                if event.kind == "pass":
                    passes += 1
                elif event.kind == "failure":
                    failures += 1
                elif event.kind == "crash":
                    crashes += 1

                if not self.hide_passed or event.kind != 'pass':
                    print(f'\r\x1b[K', *event.as_strings(), sep='', flush=True)
                    if self.bail_on_fail:
                        break

            else:
                crashes += 1
                print(f'\r\x1b[K{event}', flush=True)
                if self.bail_on_fail:
                    break

        executor.shutdown(wait=False, cancel_futures=True)
        unknown = len(self.tests) - passes - failures - crashes

        print('\r\x1b[K', end='')
        print("  ".join(
            pattern
            .replace("{}", str(cnt))
            .replace("{s}", "" if cnt == 1 else "s")
            for pattern, cnt in
            [
                ("\x1b[32m{} test{s} passed\x1b[0m", passes),
                ("\x1b[93m{} test{s} skipped\x1b[0m", self.skips),
                ("\x1b[91m{} test{s} failed\x1b[0m", failures),
                ("\x1b[95m{} test{s} crashed\x1b[0m", crashes),
                ("\x1b[36m{} not tested\x1b[0m", unknown),
            ]
            if cnt > 0
        ))

        if failures > 0 or crashes > 0:
            raise SystemExit(1)


def main():
    parser = argparse.ArgumentParser(description='sunwalker-box integrity checker')
    parser.add_argument('--box', required=True, help='Path to sunwalker_box executable')
    parser.add_argument('--arch', required=True, help='Target architecture')
    parser.add_argument('--cores', default=[0], type=int, nargs='*', help='List of cores for parallel testing')
    parser.add_argument('--block', default=[], nargs='*', help='List of tests to explicitly disable (defaults to nothing)')
    parser.add_argument('--allow', default=[], nargs='*', help='List of tests to explicitly enable (defaults to all tests)')
    parser.add_argument('--logs', default='none', choices=['none', 'impossible', 'warn', 'notice'], help='sunwalker-box logging verbosity')
    parser.add_argument('--hide-passed', action='store_true', help='Hide status for passed tests')
    parser.add_argument('--bail-on-fail', action='store_true', help='Bail on first error')
    parser.add_argument(
        '--current-status',
        default='show' if os.isatty(1) else 'hide',
        choices=['show', 'hide'],
        help='Controls whether the status line will be shown. Defaults to `show` for tty, and `hide` otherwise'
    )
    args = parser.parse_args()

    config = sunwalker_box.BoxConfig(
        executable=args.box,
        logs=args.logs
    )

    with sunwalker_box.CoreIsolator(config, set(args.cores)):
        with Tester(
            box_config=config,
            arch=args.arch,
            allow=set(args.allow),
            block=set(args.block),
            hide_passed=args.hide_passed,
            bail_on_fail=args.bail_on_fail,
            current_status=args.current_status,
        ) as tester:
            tester.register()
            tester.prepare()
            tester.run(args.cores)


if __name__ == "__main__":
    main()
