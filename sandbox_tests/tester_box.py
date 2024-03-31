import dataclasses
import enum
import itertools
import json
import os
import pprint
import subprocess
from typing import Callable, Optional, Tuple

import sunwalker_box


def parse_size(s: str) -> float:
    if " " not in s.strip():
        return float(s)
    value, unit = s.split()
    return float(value) * {
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
        "ms": 0.001,
        "s": 1,
    }[unit]


def parse_approximate_value(s: str, value_parser: Callable[[str], float]) -> tuple[float, float]:
    value, error = s.split("+-")
    value = value_parser(value)
    if error.endswith("%"):
        percentage = float(error[:-1])
        error = percentage * value
    else:
        error = value_parser(error)
    return (value - error, value + error)


def Metrics(
    cpu_time: Optional[float | str] = None,
    idleness_time: Optional[float | str] = None,
    real_time: Optional[float | str] = None,
    memory: Optional[int | str] = None,
    processes: Optional[int] = None,
) -> sunwalker_box.Metrics:
    if type(cpu_time) is str:
        cpu_time = parse_size(cpu_time)
    if type(idleness_time) is str:
        idleness_time = parse_size(idleness_time)
    if type(real_time) is str:
        real_time = parse_size(real_time)
    if type(memory) is str:
        memory = int(parse_size(memory))

    return sunwalker_box.Metrics(
        cpu_time=cpu_time,
        idleness_time=idleness_time,
        real_time=real_time,
        memory=memory,
        processes=processes,
    )


def ApproximateMetrics(
    cpu_time: Optional[str | Tuple[float, float]] = None,
    idleness_time: Optional[str | Tuple[float, float]] = None,
    real_time: Optional[str | Tuple[float, float]] = None,
    memory: Optional[str | Tuple[float, float]] = None,
) -> sunwalker_box.ApproximateMetrics:
    if type(cpu_time) is str:
        cpu_time = parse_approximate_value(cpu_time, parse_size)
    if type(idleness_time) is str:
        idleness_time = parse_approximate_value(idleness_time, parse_size)
    if type(real_time) is str:
        real_time = parse_approximate_value(real_time, parse_size)
    if type(memory) is str:
        memory = parse_approximate_value(memory, parse_size)

    return sunwalker_box.ApproximateMetrics(
        cpu_time=cpu_time,
        idleness_time=idleness_time,
        real_time=real_time,
        memory=memory,
    )


class OutputMatcher:
    def expect_match(self, value: bytes, desc: str = ""):
        ...


@dataclasses.dataclass
class FixedOutput(OutputMatcher):
    value: bytes = b""
    unordered: bool = False

    def expect_match(self, value: bytes, desc: str = ""):
        patched = value
        if self.unordered:
            patched = b"\n".join(sorted(patched.split(b"\n")))

        patched_expected = self.value
        if self.unordered:
            patched_expected = b"\n".join(sorted(patched_expected.split(b"\n")))

        assert patched == patched_expected, f"Expected {desc}: {self.value}, actual: {value}"


@dataclasses.dataclass
class PreviousOutput(OutputMatcher):
    unordered: bool = False
    value: Optional[bytes] = None
    patched: Optional[bytes] = None
    bias: Optional[str] = None  # +- ...

    def expect_match(self, value: bytes, desc: str = ""):
        patched = value
        if self.unordered:
            patched = b"\n".join(sorted(patched.split(b"\n")))

        if self.value is None:
            self.value = value
            self.patched = patched
            return

        err_text = f"Expected {desc} to match the value from the first run: {self.value}, actual: {value}"
        if self.bias is None:
            assert patched == self.patched, err_text
            return

        prev = self.patched.decode().split()
        curr = patched.decode().split()
        assert len(prev) == len(curr), f"Different lengths of {desc} values: current: {curr}, previous: {prev}"

        for prev, new in zip(prev, curr):
            l, r = parse_approximate_value(prev + self.bias, float)
            assert l <= float(new) <= r, err_text


@dataclasses.dataclass
class CompletedTestRun(sunwalker_box.CompletedRun):
    context: Optional[str] = None

    def __init__(self, completed: sunwalker_box.CompletedRun, context: Optional[str] = None):
        # TODO Find a better way.
        self.verdict = completed.verdict
        self.metrics = completed.metrics
        self.stdio = completed.stdio
        self.context = context


class Box(sunwalker_box.Box):

    def run(
        self,
        run: sunwalker_box.Run,
        input: Optional[str] = None,
        stdio: Optional[sunwalker_box.Stdio] = None,
        limits: Optional[sunwalker_box.Metrics] = None,
        context: Optional[str] = None
    ) -> CompletedTestRun:
        try:
            limits = limits or sunwalker_box.Metrics()
            stdio = stdio or sunwalker_box.Stdio()
            stdio.stdout = stdio.stdout or "/space/stdout.txt"
            stdio.stderr = stdio.stderr or "/space/stderr.txt"

            if input is None:
                stdio.stdin = None
            else:
                stdio.stdin = stdio.stdin or "/space/stdin.txt"
                self.mkfile(stdio.stdin, input.encode())

            result = super().run(run, stdio, limits)

            return CompletedTestRun(result, context)

        except Exception as e:
            if context is not None:
                e.add_note(f"Context: {context}")
            raise

    def expect(
        self,
        completed: CompletedTestRun,
        verdict: sunwalker_box.BaseVerdict = sunwalker_box.Exited(0),
        metrics: sunwalker_box.ApproximateMetrics = sunwalker_box.ApproximateMetrics(),
        stdout: OutputMatcher | bytes | str = OutputMatcher(),
        stderr: OutputMatcher | bytes | str = OutputMatcher()
    ) -> dict[str, OutputMatcher]:

        if type(stdout) is str:
            stdout = stdout.encode()
        if type(stdout) is bytes:
            stdout = FixedOutput(stdout)

        if type(stderr) is str:
            stderr = stderr.encode()
        if type(stderr) is bytes:
            stderr = FixedOutput(stderr)

        try:
            if completed.stdio.stdout is not None:
                with self.open(completed.stdio.stdout, 'rb') as f:
                    stdout_bytes = f.read()

            if completed.stdio.stderr is not None:
                with self.open(completed.stdio.stderr, 'rb') as f:
                    stderr_bytes = f.read()

            super().expect(completed, verdict, metrics)

            if completed.stdio.stdout is not None:
                stdout.expect_match(stdout_bytes, "stdout")

            if completed.stdio.stderr is not None:
                stderr.expect_match(stderr_bytes, "stderr")

        except BaseException as e:
            # TODO: This is not, in fact, pretty.
            pretty_result = pprint.pformat(completed, width=100, compact=True)
            e.add_note(f"Run stats: {pretty_result}")

            e.add_note(f"stdout: {locals().get('stdout_bytes')}")
            e.add_note(f"stderr: {locals().get('stderr_bytes')}")

            if completed.context is not None:
                e.add_note(f"Context: {completed.context}")

            raise e

        return dict(stdout=stdout, stderr=stderr)
