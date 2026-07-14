"""Budget governor for bounded autonomous operation.

Caps tokens, tool/model calls, and wall-clock time so a long or looping run stops
instead of consuming unboundedly. The clock is injectable so the accounting is
deterministically testable.

This governs resource consumption only. It is not a safety boundary against
malicious behavior — that is the sandbox's job.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Callable


class BudgetExceeded(RuntimeError):
    """Raised when a charge would exceed a configured cap."""


@dataclass
class Budget:
    max_tokens: int | None = None
    max_calls: int | None = None
    max_wall_s: float | None = None
    clock: Callable[[], float] = time.monotonic

    def __post_init__(self) -> None:
        self._tokens = 0
        self._calls = 0
        self._start = self.clock()

    @property
    def tokens(self) -> int:
        return self._tokens

    @property
    def calls(self) -> int:
        return self._calls

    def elapsed_s(self) -> float:
        return self.clock() - self._start

    def exceeded(self) -> bool:
        if self.max_tokens is not None and self._tokens > self.max_tokens:
            return True
        if self.max_calls is not None and self._calls > self.max_calls:
            return True
        if self.max_wall_s is not None and self.elapsed_s() > self.max_wall_s:
            return True
        return False

    def _raise_if_exceeded(self) -> None:
        if self.exceeded():
            raise BudgetExceeded(
                f"budget exceeded: tokens={self._tokens}/{self.max_tokens} "
                f"calls={self._calls}/{self.max_calls} "
                f"elapsed={self.elapsed_s():.1f}/{self.max_wall_s}"
            )

    def charge_tokens(self, n: int) -> None:
        self._tokens += n
        self._raise_if_exceeded()

    def charge_call(self, n: int = 1) -> None:
        self._calls += n
        self._raise_if_exceeded()

    def check_time(self) -> None:
        """Check the wall-clock cap without charging tokens/calls."""
        self._raise_if_exceeded()
