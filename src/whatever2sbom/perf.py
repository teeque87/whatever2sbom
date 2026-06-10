"""
Lightweight, opt-in performance instrumentation.

Disabled (`enabled = False`) by default, so normal runs pay no overhead and
print nothing. The CLI flips `enabled` on when --performance-metrics is
passed, and calls `report()` once the run finishes to print a timing
breakdown of the pipeline stages.
"""

from __future__ import annotations

import sys
import time
from contextlib import ContextDecorator

enabled = False
_records: list[tuple[str, float]] = []


class timed(ContextDecorator):
    """Time a block (or decorated function) and record it under `label`.

    No-op unless `perf.enabled` is True, so it is safe to leave in place
    around hot code paths.
    """

    def __init__(self, label: str) -> None:
        self.label = label

    def __enter__(self) -> "timed":
        self._start = time.perf_counter()
        return self

    def __exit__(self, *exc_info: object) -> bool:
        if enabled:
            _records.append((self.label, time.perf_counter() - self._start))
        return False


def reset() -> None:
    """Clear all recorded timings."""
    _records.clear()


def report(file: object = None) -> None:
    """Print a breakdown of all recorded timings, plus their total."""
    if not _records:
        return
    file = file or sys.stderr
    width = max(len(label) for label, _ in _records)
    print("Performance metrics:", file=file)
    for label, elapsed in _records:
        print(f"  {label:<{width}} : {elapsed * 1000:9.2f} ms", file=file)
    total = sum(elapsed for _, elapsed in _records)
    print(f"  {'total':<{width}} : {total * 1000:9.2f} ms", file=file)
