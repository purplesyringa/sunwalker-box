#!/usr/bin/env python3
import argparse
import conductor
import dataclasses
import io
import json
import os
import re
import shutil
import subprocess
import sys
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
        self.preparable = self.root is not None or self.assets is not None

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

    def prepare(self):
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

    @staticmethod
    def extract_header(path):
        ...

    def build(self, error: queue.Queue):
        ...

    def needs_build(self):
        return False


class CTest(Test):
    buildable = True

    def __post_init__(self):
        self._source = f'tests/{self.slug}.c'
        self._binary = f'build/{self.slug}'

        super().__post_init__()

    def _test_compiler(self, name):
        try:
            return 'musl' in subprocess.run([name, '-v'], capture_output=True, text=True).stderr
        except Exception as e:
            return False

    def build(self, error):
        ccflags = ["-static"] if self.static else []

        for compiler in ['gcc', 'musl-gcc']:
            if self._test_compiler(compiler):
                cc = compiler
                break
        else:
            assert False, "Could not find working musl-gcc in PATH"

        result = subprocess.run(
            [cc, '-fdiagnostics-color=always', self._source, '-o', self._binary] + ccflags,
            capture_output=True,
            check=False,
            text=True
        )

        error.put(f'Compiler {result.args} exited with code {result.returncode}\n')
        error.put(result.stderr)
        assert not result.stderr

    def needs_build(self):
        try:
            return os.path.getmtime(self._source) >= os.path.getmtime(self._binary)
        except FileNotFoundError:
            return True

    def bind(self, box: sunwalker_box.Box):
        if self.files_committed:
            return

        path = f"/space/{self.slug}"
        self.argv = [path]
        box.touch(path)
        box.bind(os.path.abspath(self._binary), path, readonly=True)

    @staticmethod
    def extract_header(path):
        with open(path) as f:
            return re.match(r"/\*([\s\S]+?)\*/", f.read()).group(1)


class PyTest(Test):
    def bind(self, box: sunwalker_box.Box):
        if self.files_committed:
            return

        path = f"/space/{self.slug}.py"
        self.argv = ["/usr/bin/python3", path]
        box.touch(path)
        box.bind(os.path.abspath(f"tests/{self.slug}.py"), path, readonly=True)

    @staticmethod
    def extract_header(path):
        with open(path) as f:
            return re.match(r'"""([\s\S]+?)"""', f.read()).group(1)


class YamlTest(Test):
    @staticmethod
    def extract_header(path):
        with open(path) as f:
            return f.read()


@dataclasses.dataclass
class Builder:
    slug: str
    short_description: str
    description: str
    test: Test

    def run(self, _core, error: queue.Queue):
        self.test.build(error)


@dataclasses.dataclass
class Preparer:
    slug: str
    short_description: str
    description: str
    test: Test

    def run(self, _core, error: queue.Queue):
        self.test.prepare()


@dataclasses.dataclass
class Invoker:
    slug: str
    short_description: str
    description: str
    test: Test
    script: str
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

    def run(self, core: int, error: queue.Queue, box_config: sunwalker_box.BoxConfig):
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
class Tester:
    box_config: sunwalker_box.BoxConfig
    arch: str
    cpus: list[int]
    allow: Optional[set[str]] = None
    block: Optional[set[str]] = None
    conductor_args: Optional[dict[str, ...]] = None

    def register(self):
        self.builders: list[Builder] = []
        self.preparers: list[Preparer] = []
        self.tests: list[Invoker] = []
        for test_file in os.listdir("tests"):
            slug, ext = test_file.rsplit(".", 1)
            if slug in (self.block or set()) or slug not in (self.allow or slug):
                continue

            test_class = dict(c=CTest, py=PyTest, yaml=YamlTest)[ext]

            yaml_header = test_class.extract_header(os.path.join("tests", test_file))
            header = yaml.unsafe_load(yaml_header)

            if self.arch not in (header.get("arch") or self.arch):
                continue

            test = test_class(slug, **{key: header.get(key) for key in "static root assets".split()})

            if test.needs_build():
                self.builders.append(Builder(slug, f"Compile {slug}", test=test, description=f"Compile steps for {slug}"))

            if test.preparable:
                self.preparers.append(Preparer(slug, f"Prepare {slug}", test=test, description=f"Prepare environment for {slug}"))

            self.tests.append(Invoker(
                slug,
                f"Test {slug}",
                test=test,
                **{key: header.get(key) for key in "description script outer_env quotas slow".split()}
            ))

    def build(self):
        os.makedirs("build", exist_ok=True)

        if not conductor.Conductor('builder', 'Compiling', 'Compiled', self.builders, **self.conductor_args).run(self.cpus):
            raise SystemExit(1)

    def prepare(self):
        os.makedirs("build/roots", exist_ok=True)
        os.makedirs("build/assets", exist_ok=True)

        if not conductor.Conductor('preparer', 'Preparing', 'Prepared', self.preparers, **self.conductor_args).run(self.cpus):
            raise SystemExit(1)

    def run(self):
        args = self.conductor_args | dict(intermediate_status=True)
        if not conductor.Conductor('invoker', 'Testing', 'Tested', self.tests, **args).run(self.cpus, self.box_config):
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
        '--intermediate-status',
        default='show',
        choices=['show', 'hide'],
        help='Controls whether intermediate statuses will persist'
    )
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
        tester = Tester(
            box_config=config,
            arch=args.arch,
            cpus=args.cores,
            allow=set(args.allow),
            block=set(args.block),

            conductor_args=dict(
                hide_passed=args.hide_passed,
                bail_on_fail=args.bail_on_fail,
                intermediate_status=args.intermediate_status == 'show',
                current_status=args.current_status == 'show',
            ),
        )
        tester.register()
        tester.build()
        tester.prepare()
        tester.run()


if __name__ == "__main__":
    main()
