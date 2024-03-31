#!/usr/bin/env python3
import contextlib
import dataclasses
import io
import json
import os
import re
import shutil
import subprocess
import sys
import time
import traceback
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

    def prepare(self, tester):
        if self.root is not None:
            self.root_dir = f"build/roots/{self.slug}"
            if os.path.isdir(self.root_dir):
                shutil.rmtree(self.root_dir)
            os.mkdir(self.root_dir)

            create_dirs(self.root, self.root_dir)

        if self.assets is not None:
            self.assets_dir = f"build/assets/{self.slug}"
            if os.path.isdir(self.assets_dir):
                shutil.rmtree(self.assets_dir)
            os.mkdir(self.assets_dir)

            create_dirs(self.assets, self.assets_dir)

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

    def __post_init__(self):
        if self.outer_env is None:
            self.outer_env = {}
        if self.quotas is None:
            self.quotas = {}

    def prepare(self, tester):
        self.test.prepare(tester)

    def run(self, tester, core: int):
        for key, value in self.outer_env.items():
            os.environ[key] = value

        with Box(
            tester.box_config,
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
                print(f"Executed script:\n{script}")
                raise


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


@dataclasses.dataclass
class Tester:
    box_config: sunwalker_box.BoxConfig
    arch: str
    whitelist: Optional[set[str]] = None

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
            if slug not in (self.whitelist or slug):
                self.skips += 1
                continue

            test_class: Test
            with open(os.path.join("tests", test_file)) as f:
                if ext == "c":
                    yaml_header = re.match(r"/\*([\s\S]+?)\*/", f.read()).group(1)
                    test_class = CTest
                elif ext == "py":
                    yaml_header = re.match(r"\"\"\"([\s\S]+?)\"\"\"", f.read()).group(1)
                    test_class = PyTest
                elif ext == "yaml":
                    yaml_header = f.read()
                    test_class = YamlTest

            header = yaml.unsafe_load(yaml_header)
            if self.arch not in (header.get("arch") or self.arch):
                self.skips += 1
                continue

            # I AM NORMAL I AM PERFECTLY SANE
            self.tests.append(SingleTest(
                slug,
                test=test_class(slug, **{key: header.get(key) for key in "static root assets".split()}),
                **{key: header.get(key) for key in "description script arch outer_env quotas".split()}
            ))

    def prepare(self):
        for test in self.tests:
            test.prepare(self)

        self.f_makefile.write("all: " + " ".join(self.make_targets))
        self.f_makefile.close()

        subprocess.run(["make", "-C", "build", "all"], check=True)

    def run(self):
        passes = 0
        failures = 0
        crashes = 0

        for test in sorted(self.tests, key=lambda test: test.slug):
            print(f"          [{test.slug}]", end="", flush=True)

            buf_stdout = io.StringIO()

            start_time = time.time()
            try:
                with contextlib.redirect_stdout(buf_stdout):
                    # TODO multicore support
                    test.run(self, 1)
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
                    print('   ', '\n    '.join(ex[0].__notes__))
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
                ("\x1b[93m{} test{s} skipped\x1b[0m", self.skips),
                ("\x1b[91m{} test{s} failed\x1b[0m", failures),
                ("\x1b[95m{} test{s} crashed\x1b[0m", crashes)
            ]
            if cnt > 0
        ))
        if failures > 0 or crashes > 0:
            raise SystemExit(1)


def main():
    # TODO make me pretty
    config = sunwalker_box.BoxConfig()
    arch = sys.argv[1]
    test_whitelist = sys.argv[2].split(",") if len(sys.argv) >= 3 else None

    with sunwalker_box.CoreIsolator(config, {1}):
        with Tester(config, arch, test_whitelist) as tester:
            tester.register()
            tester.prepare()
            tester.run()


if __name__ == "__main__":
    main()
