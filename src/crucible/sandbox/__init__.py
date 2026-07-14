"""Sandboxed execution for proof-of-concept validation.

The PoC gate is the only gate that can produce a deterministic result: a PoC
either executes and demonstrates the issue or it does not. This package provides
the executor abstraction and two implementations:

- ``LocalSubprocessExecutor`` — runs the PoC as a subprocess. Fast and used in
  tests, but it does NOT isolate untrusted code. Only use it on PoCs you trust
  (e.g. hand-written test PoCs). See its docstring.
- ``DockerExecutor`` — runs the PoC in a container with networking disabled and
  resource limits. This is the intended path for model-generated PoCs. It shells
  out to ``docker`` and is NOT run in CI.

PoC exit-code contract: a PoC exits 0 to signal it successfully demonstrated the
vulnerability, and non-zero otherwise. Executors report the raw result; the PoC
gate applies this contract.
"""

from crucible.sandbox.base import ExecutionResult, ExecutionStatus, SandboxExecutor
from crucible.sandbox.local import LocalSubprocessExecutor

__all__ = [
    "ExecutionResult",
    "ExecutionStatus",
    "SandboxExecutor",
    "LocalSubprocessExecutor",
]
