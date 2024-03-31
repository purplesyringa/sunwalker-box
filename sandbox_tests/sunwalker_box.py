import dataclasses
import enum
import itertools
import json
import os
import pprint
import subprocess
from typing import Callable, Optional, Tuple


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


def _ignore_unset_values(dataclass) -> dict[str, ...]:
    return filter(lambda kv: kv[1] is not None, dataclasses.asdict(dataclass).items())


@dataclasses.dataclass(kw_only=True)
class Metrics:
    cpu_time: Optional[float] = None  # in seconds
    real_time: Optional[float] = None  # in seconds
    idleness_time: Optional[float] = None  # in seconds
    memory: Optional[int] = None  # in bytes
    processes: Optional[int] = None

    def as_limits_dict(self):
        return dict(map(lambda kv: (kv[0] + "_limit", kv[1]), _ignore_unset_values(self)))


@dataclasses.dataclass(kw_only=True)
class ApproximateMetrics:
    cpu_time: Optional[Tuple[float, float]] = None
    idleness_time: Optional[Tuple[float, float]] = None
    real_time: Optional[Tuple[float, float]] = None
    memory: Optional[Tuple[float, float]] = None

    def _expect(self, key: str, value: Optional[float], lr: Optional[Tuple[float, float]]):
        assert lr is None or (lr[0] <= value <= lr[1]), f"Unexpected {key}: value {value} is not between {lr[0]} and {lr[1]}"

    def expect_match(self, metrics: Metrics):
        self._expect('cpu_time', metrics.cpu_time, self.cpu_time)
        self._expect('idleness_time', metrics.idleness_time, self.idleness_time)
        self._expect('real_time', metrics.real_time, self.real_time)
        self._expect('memory', metrics.memory, self.memory)


@dataclasses.dataclass(kw_only=True)
class Stdio:
    stdin: Optional[str] = None
    stdout: Optional[str] = None
    stderr: Optional[str] = None

    def as_dict(self):
        return dict(_ignore_unset_values(self))


@dataclasses.dataclass
class Run:
    argv: list[str]
    env: dict[str, str] = dataclasses.field(default_factory=lambda: DEFAULT_ENV)

    def __post_init__(self):
        if self.env is None:
            self.env = DEFAULT_ENV

    def as_dict(self):
        return dict(_ignore_unset_values(self))


@dataclasses.dataclass(kw_only=True)
class Quota:
    space: Optional[int] = None  # in bytes
    inodes: Optional[int] = None

    def as_kv(self):
        return map(lambda kv: ("quota-" + kv[0], kv[1]), _ignore_unset_values(self))


@dataclasses.dataclass()
class BoxConfig:
    executable: str = "../sunwalker_box"
    logs: Optional[str] = None

    def as_opts(self):
        yield self.executable

        if self.logs:
            yield from ("--logs", self.logs)

    def run(self, opts: list[str] = [], *args):
        return subprocess.Popen(
            itertools.chain(self.as_opts(), opts, args),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE
        )


@dataclasses.dataclass(kw_only=True)
class Config:
    core: int = 1
    root: Optional[str] = None
    quotas: Optional[Quota] = None

    def as_opts(self):
        yield "start"

        if self.core is not None:
            yield from ("--core", str(self.core))

        if self.root:
            yield from ("--root", self.root)

        if self.quotas:
            for quota, limit in self.quotas.as_kv():
                yield from ("--" + quota, str(limit))


Limit = enum.Enum('Limit', "cpu_time real_time idleness_time memory".split())


class BaseVerdict:
    ...


@dataclasses.dataclass
class Exited(BaseVerdict):
    exit_code: int


@dataclasses.dataclass
class Signaled(BaseVerdict):
    signal: int


@dataclasses.dataclass
class Limited(BaseVerdict):
    limit: Limit


@dataclasses.dataclass
class CompletedRun:
    verdict: BaseVerdict
    metrics: Metrics
    stdio: Stdio


class Box:
    def __init__(self, box: BoxConfig, opts: Optional[Config] = None):
        self.proc = box.run(opts.as_opts())

    def __enter__(self):
        self.update_extpath()
        return self

    def __exit__(self, exc_type, exc_value, exc_traceback):
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

    def update_extpath(self):
        self.root_path = self.cmd("extpath", "/")

    def extpath(self, where: str):
        return self.root_path + where

    def bind(self, source: str, mountpoint: str, readonly: bool = False):
        return self.cmd("bind", {"external": source, "internal": mountpoint, "ro": readonly})

    def reset(self):
        res = self.cmd("reset")
        self.update_extpath()
        return res

    def commit(self):
        return self.cmd("commit")

    def command_run(self, run: Run, stdio: Optional[Stdio] = None, limits: Optional[Metrics] = None) -> dict[str, ...]:
        return self.cmd("run", run.as_dict() | limits.as_limits_dict() | stdio.as_dict())

    def open(self, path: str, *args, **kwargs):
        return open(self.extpath(path), *args, **kwargs)

    def mkdir(self, path: str, owner: str = "root", mode: int = 0o755):
        path = self.extpath(path)
        os.makedirs(path, mode, exist_ok=True)
        uid = 1 if "root" == owner else 2
        os.chown(path, uid, uid)

    def mkfile(self, path: str, content: bytes = b'', owner: str = "root", mode: int = 0o755):
        path = self.extpath(path)
        with open(path, 'wb') as f:
            f.write(content)
        os.chmod(path, mode)
        uid = 1 if "root" == owner else 2
        os.chown(path, uid, uid)

    def touch(self, path: str):
        # see https://stackoverflow.com/a/6222692
        try:
            os.utime(self.extpath(path), None)
        except OSError:
            self.mkfile(path)

    def _parse_run_result(self, result: dict[str, ...]) -> (BaseVerdict, Metrics):
        verdict = {
            "OK": Exited(result.get("exit_code")),
            "Signaled": Signaled(result.get("exit_code")),
            "CPUTimeLimitExceeded": Limited(Limit.cpu_time),
            "RealTimeLimitExceeded": Limited(Limit.real_time),
            "IdlenessTimeLimitExceeded": Limited(Limit.idleness_time),
            "MemoryLimitExceeded": Limited(Limit.memory),
        }.get(result.get("limit_verdict"))

        metrics = Metrics(**{
            key: result.get(key)
            for key
            in "cpu_time real_time idleness_time memory".split()
        })

        return (verdict, metrics)

    def run(self, run: Run, stdio: Stdio, limits: Metrics) -> CompletedRun:
        result = self.command_run(run, stdio, limits)
        verdict, metrics = self._parse_run_result(result)
        return CompletedRun(verdict, metrics, stdio)

    def expect(self, result: CompletedRun, verdict: BaseVerdict | type, metrics: ApproximateMetrics):
        assert verdict == result.verdict or type(result.verdict) is verdict, f"Unexpected verdict: {result.verdict} is not {verdict}"
        metrics.expect_match(result.metrics)


@dataclasses.dataclass
class CoreIsolator:
    box: BoxConfig
    cores: set[int] = dataclasses.field(default_factory=lambda: {1})

    def __enter__(self):
        for core in self.cores:
            assert not self.box.run(f"isolate -c {core}".split()).poll()
        return self

    def __exit__(self, exc_type, exc_value, exc_traceback):
        for core in self.cores:
            assert not self.box.run(f"free -c {core}".split()).poll()
