from concurrent.futures import ThreadPoolExecutor
import dataclasses
import time
import threading
import traceback
import queue
from typing import Optional


@dataclasses.dataclass
class EventStarted:
    slugslug: str
    slug: str


@dataclasses.dataclass
class EventFinished:
    slugslug: str
    slug: str
    description: str
    duration: float
    error: queue.Queue
    ex: Optional[Exception] = None
    trace: Optional[str] = None

    def __post_init__(self):
        if not self.ex:
            self.kind = "pass"
        elif isinstance(self.ex, AssertionError):
            self.kind = "failure"
        else:
            self.kind = "crash"

    def as_strings(self):
        time_text = f"{self.duration:.1f}s" if (self.duration or 0) > 0.1 else "    "
        yield f"\x1b[36m{time_text}\x1b[0m "

        status = "\x1b[32m OK \x1b[0m" if self.kind == "pass" else "\x1b[91mFAIL\x1b[0m"
        yield f'{status} {self.slug}'

        if self.kind != "pass":
            yield '\n'
            yield f"\x1b[36m  {self.description}\x1b[0m\n"

            while not self.error.empty():
                message = self.error.get_nowait()
                yield from ('  --- executor message ---\n    ', message.replace('\n', '\n    '), '\n')

            if self.kind == "failure":
                yield from ("\x1b[33m  ", str(self.ex).replace("\n", "\n  "), "\x1b[0m\n")
                try:
                    yield from ('    ', '\n    '.join(self.ex.__notes__))
                except AttributeError:
                    pass
            elif self.kind == "crash":
                yield from ("\x1b[95m", self.ex, "\x1b[0m\n", self.trace)


class Conductor:
    def __init__(self, name, action, end_action, actions, current_status=True, intermediate_status=False, hide_passed=True, bail_on_fail=True):
        self.name = name
        self.action = action
        self.end_action = end_action
        self.actions = actions

        self.current_status = current_status
        self.intermediate_status = intermediate_status
        self.hide_passed = hide_passed
        self.bail_on_fail = bail_on_fail

        self.count = 0
        self.passes = 0
        self.failures = 0
        self.crashes = 0
        self.current = set()
        self.feedback = queue.Queue()

    def is_running(self):
        return self.count != len(self.actions)

    def as_strings(self):
        _italic = "\x1b[3m"
        _reset = "\x1b[0m"
        running = self.is_running()

        yield '\r\x1b[K'

        action = self.action if running else self.end_action
        yield f"{action} [{self.count}/{len(self.actions)}]"

        for pattern, cnt in [
            ("\x1b[32m{} passed", self.passes),
            ("\x1b[91m{} failed", self.failures),
            ("\x1b[95m{} crashed", self.crashes),
            ("\x1b[36m{} not executed", len(self.actions) - self.count),
        ]:
            if cnt > 0:
                yield from ('  ', pattern.format(cnt), _reset)

        if running:
            yield ' -- '
            yield ", ".join(map(lambda item: f"\x1b[3m{item}{_reset}", self.current))
            yield '...'

    def print_status(self):
        print(*self.as_strings(), flush=True, sep='', end='')

    def _started(self, event):
        self.current.add(event.slugslug)
        return True

    def _finished(self, event):
        self.current.remove(event.slugslug)
        self.count += 1

        if event.kind == "pass":
            self.passes += 1
        elif event.kind == "failure":
            self.failures += 1
        elif event.kind == "crash":
            self.crashes += 1

        if not self.hide_passed or event.kind != 'pass':
            print(f'\r\x1b[K', *event.as_strings(), sep='', flush=True)

        return event.kind == "pass" or not self.bail_on_fail

    def _unknown(self, event):
        self.crashes += 1
        print(f'\r\x1b[K{event}', flush=True)
        return not self.bail_on_fail

    def _dispatch_event(self):
        if self.current_status:
            self.print_status()

        event = self.feedback.get()

        if type(event) is EventStarted:
            return self._started(event)
        elif type(event) is EventFinished:
            return self._finished(event)

        return self._unknown(event)

    def _run_single(self, cpus, action, args, kwargs):
        self.feedback.put(EventStarted(action.slugslug, action.slug))

        thread_name = threading.current_thread().name
        cpu_index = int(thread_name.rsplit('_', 1)[1])
        cpu = cpus[cpu_index]

        error = queue.Queue()
        start_time = time.time()
        try:
            res = action.run(cpu, error, *args, **kwargs)
        except Exception as e:
            ex, trace = e, traceback.format_exc()
        else:
            ex, trace = None, None
        finally:
            duration = time.time() - start_time

        self.feedback.put(EventFinished(
            action.slugslug,
            action.slug,
            action.description,
            ex=ex,
            trace=trace,
            duration=duration,
            error=error,
        ))

    def _run_single_wrapper(self, *args, **kwargs):
        # We don't wait on futures, thus we can't deliver unexpected exceptions. A simple workaround is enough for debugging purposes
        try:
            self._run_single(*args, **kwargs)
        except BaseException:
            print(traceback.format_exc(), flush=True)

    def run(self, cpus, /, *args, **kwargs):
        executor = ThreadPoolExecutor(max_workers=len(cpus), thread_name_prefix=self.name)
        for action in self.actions:
            executor.submit(self._run_single_wrapper, cpus, action, args, kwargs)

        try:
            while self.is_running() and self._dispatch_event():
                continue
        except KeyboardInterrupt:
            print()
            return False

        executor.shutdown(wait=False, cancel_futures=True)
        self.print_status()
        if self.intermediate_status:
            print()

        return self.count == self.passes
