"""Executor abstraction shared by the local and Docker sandbox backends."""

from __future__ import annotations

import abc
import enum
from dataclasses import dataclass, field


class ExecutionStatus(enum.Enum):
    OK = "ok"            # process exited 0
    FAILED = "failed"    # process exited non-zero
    TIMEOUT = "timeout"  # process exceeded the wall-clock limit
    ERROR = "error"      # could not run (missing runtime, executor fault)


@dataclass
class ExecutionResult:
    status: ExecutionStatus
    exit_code: int | None
    stdout: str
    stderr: str
    duration_s: float
    # True only if the executor actually enforced network isolation. The local
    # executor cannot, so it reports False; the Docker executor reports True.
    network_isolated: bool = False
    meta: dict = field(default_factory=dict)

    @property
    def fired(self) -> bool:
        """PoC contract: exit 0 means the PoC demonstrated the issue."""
        return self.status is ExecutionStatus.OK


class SandboxExecutor(abc.ABC):
    """Runs a set of files and an entrypoint, returns an ExecutionResult.

    Implementations must never raise for an ordinary failed/timed-out PoC — that
    is a normal result (``FAILED``/``TIMEOUT``). They may return ``ERROR`` when
    the runtime itself is unavailable.
    """

    name: str = "abstract"

    @abc.abstractmethod
    def run(
        self,
        files: dict[str, str],
        entrypoint: list[str],
        *,
        timeout_s: float = 30.0,
        allow_network: bool = False,
    ) -> ExecutionResult:
        raise NotImplementedError
