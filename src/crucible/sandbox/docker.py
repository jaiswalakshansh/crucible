"""Docker executor — the intended runner for model-generated PoCs.

Runs the PoC inside a container with networking disabled (``--network none``),
a read-only-ish workdir mounted from a temp directory, a memory cap, and a
wall-clock timeout. This enforces the "no untrusted input + secrets + network at
once" constraint by removing network from the equation.

Verification status: NOT run in CI and NOT exercised by the test suite (building
and running containers is slow and environment-dependent). The control flow
mirrors ``LocalSubprocessExecutor``; treat its behavior as unverified in this
repo until an integration test is added. It requires a working ``docker`` CLI.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import time

from crucible.sandbox.base import ExecutionResult, ExecutionStatus, SandboxExecutor


class DockerExecutor(SandboxExecutor):
    name = "docker"

    def __init__(self, image: str = "python:3.12-slim", *, memory: str = "512m") -> None:
        self.image = image
        self.memory = memory

    def available(self) -> bool:
        return shutil.which("docker") is not None

    def run(
        self,
        files: dict[str, str],
        entrypoint: list[str],
        *,
        timeout_s: float = 60.0,
        allow_network: bool = False,
    ) -> ExecutionResult:
        start = time.monotonic()
        if not self.available():
            return ExecutionResult(
                status=ExecutionStatus.ERROR,
                exit_code=None,
                stdout="",
                stderr="docker CLI not found",
                duration_s=0.0,
                network_isolated=False,
                meta={"error": "docker-missing"},
            )
        with tempfile.TemporaryDirectory(prefix="crucible-poc-") as workdir:
            for rel, content in files.items():
                dest = os.path.join(workdir, rel)
                os.makedirs(os.path.dirname(dest) or workdir, exist_ok=True)
                with open(dest, "w", encoding="utf-8") as fh:
                    fh.write(content)

            net = "bridge" if allow_network else "none"
            cmd = [
                "docker", "run", "--rm",
                "--network", net,
                "--memory", self.memory,
                "--pids-limit", "256",
                "-v", f"{workdir}:/poc:ro",
                "-w", "/poc",
                self.image,
                *entrypoint,
            ]
            try:
                proc = subprocess.run(
                    cmd, capture_output=True, text=True, timeout=timeout_s
                )
            except subprocess.TimeoutExpired:
                return ExecutionResult(
                    status=ExecutionStatus.TIMEOUT,
                    exit_code=None,
                    stdout="",
                    stderr="container exceeded timeout",
                    duration_s=time.monotonic() - start,
                    network_isolated=not allow_network,
                    meta={"image": self.image},
                )

        status = ExecutionStatus.OK if proc.returncode == 0 else ExecutionStatus.FAILED
        return ExecutionResult(
            status=status,
            exit_code=proc.returncode,
            stdout=proc.stdout,
            stderr=proc.stderr,
            duration_s=time.monotonic() - start,
            network_isolated=not allow_network,
            meta={"image": self.image},
        )
