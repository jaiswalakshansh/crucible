"""Local subprocess executor.

SAFETY: this executor does NOT sandbox untrusted code. It writes the given files
to a temporary directory and runs the entrypoint as a normal child process with a
timeout. It cannot block network access, filesystem access outside the temp dir,
or system calls. Use it only for PoCs you trust — hand-written test PoCs, or in a
throwaway CI runner. For model-generated PoCs use ``DockerExecutor``.

It exists because it lets the PoC gate be verified end-to-end with real execution
(no mock), and because in a disposable CI container it is an acceptable runner.
"""

from __future__ import annotations

import os
import subprocess
import tempfile
import time

from crucible.sandbox.base import ExecutionResult, ExecutionStatus, SandboxExecutor


class LocalSubprocessExecutor(SandboxExecutor):
    name = "local-subprocess"

    def run(
        self,
        files: dict[str, str],
        entrypoint: list[str],
        *,
        timeout_s: float = 30.0,
        allow_network: bool = False,
    ) -> ExecutionResult:
        start = time.monotonic()
        with tempfile.TemporaryDirectory(prefix="crucible-poc-") as workdir:
            for rel, content in files.items():
                dest = os.path.join(workdir, rel)
                os.makedirs(os.path.dirname(dest) or workdir, exist_ok=True)
                with open(dest, "w", encoding="utf-8") as fh:
                    fh.write(content)
            try:
                proc = subprocess.run(
                    entrypoint,
                    cwd=workdir,
                    capture_output=True,
                    text=True,
                    timeout=timeout_s,
                )
            except subprocess.TimeoutExpired as exc:
                return ExecutionResult(
                    status=ExecutionStatus.TIMEOUT,
                    exit_code=None,
                    stdout=exc.stdout or "" if isinstance(exc.stdout, str) else "",
                    stderr=exc.stderr or "" if isinstance(exc.stderr, str) else "",
                    duration_s=time.monotonic() - start,
                    network_isolated=False,
                    meta={"note": "local executor cannot isolate network or fs"},
                )
            except (FileNotFoundError, OSError) as exc:
                return ExecutionResult(
                    status=ExecutionStatus.ERROR,
                    exit_code=None,
                    stdout="",
                    stderr=str(exc),
                    duration_s=time.monotonic() - start,
                    network_isolated=False,
                    meta={"error": type(exc).__name__},
                )

        status = ExecutionStatus.OK if proc.returncode == 0 else ExecutionStatus.FAILED
        return ExecutionResult(
            status=status,
            exit_code=proc.returncode,
            stdout=proc.stdout,
            stderr=proc.stderr,
            duration_s=time.monotonic() - start,
            network_isolated=False,
            meta={"note": "local executor cannot isolate network or fs"},
        )
