"""End-to-end pipeline: candidates -> ladder -> consensus -> findings.

This composes the pieces that Phase 0/1/2 built into one runnable flow, with each
component injected so the whole thing is testable without a live model or scanner:

- ``candidate_source``: ``Callable[[str], list[Finding]]`` — produces candidates
  for a target (e.g. the Opengrep adapter, or an injected stub in tests).
- ``ladder``: a ``ValidationLadder`` (any set of gates).
- ``runs``: how many independent passes to make; results are merged by
  ``consensus.merge_runs`` so each finding carries a stability score.

The pipeline does not drop findings on its own. Callers apply a consensus
threshold if they want one.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from crucible.schema.finding import Finding
from crucible.validators import consensus
from crucible.validators.ladder import ValidationLadder

CandidateSource = Callable[[str], list[Finding]]


@dataclass
class Pipeline:
    candidate_source: CandidateSource
    ladder: ValidationLadder

    def _one_pass(self, target: str) -> list[Finding]:
        out: list[Finding] = []
        for finding in self.candidate_source(target):
            out.append(self.ladder.run(finding))
        return out

    def scan(self, target: str, *, runs: int = 1) -> list[Finding]:
        """Run the pipeline ``runs`` times and merge with stability scores."""
        if runs < 1:
            raise ValueError("runs must be >= 1")
        passes = [self._one_pass(target) for _ in range(runs)]
        return consensus.merge_runs(passes)
