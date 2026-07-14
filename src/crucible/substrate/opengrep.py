"""Opengrep adapter — the deterministic detector floor.

Opengrep is the open fork of Semgrep with cross-function taint across 12
languages and byte-compatible SARIF/rule formats. We shell out to it and parse
its SARIF into Crucible ``Finding`` objects tagged ``source="opengrep"``.

This is Gate 0 of the pipeline: cheap, deterministic candidates that the LLM
ladder then investigates. Grounding the model in real taint output (rather than
raw file dumps) is what the research shows separates 14%-TPR agents from useful
ones. If the ``opengrep`` binary is absent, ``available()`` returns False and the
caller degrades to LLM-only recon rather than crashing.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from typing import Any

from crucible.schema.finding import Finding


class OpengrepAdapter:
    def __init__(self, binary: str = "opengrep", config: str = "auto") -> None:
        self.binary = binary
        self.config = config

    def available(self) -> bool:
        return shutil.which(self.binary) is not None

    def scan(self, target: str, *, timeout: int = 900) -> list[Finding]:
        """Run Opengrep over ``target`` and return parsed findings.

        Raises ``FileNotFoundError`` if the binary is missing — callers should
        check ``available()`` first and degrade gracefully.
        """
        if not self.available():
            raise FileNotFoundError(
                f"{self.binary!r} not found on PATH. Install Opengrep or run "
                f"with --no-opengrep to use LLM-only recon."
            )
        proc = subprocess.run(
            [self.binary, "--config", self.config, "--sarif", "--quiet", target],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        # Opengrep exits non-zero when findings exist; only treat a missing/empty
        # SARIF payload as a real failure.
        if not proc.stdout.strip():
            raise RuntimeError(f"opengrep produced no output; stderr: {proc.stderr[:500]}")
        return self.parse_sarif(json.loads(proc.stdout))

    @staticmethod
    def parse_sarif(sarif: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        for run in sarif.get("runs", []):
            for result in run.get("results", []):
                findings.append(Finding.from_sarif_result(result, source="opengrep"))
        return findings
