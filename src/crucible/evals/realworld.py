"""Measure Crucible against a real application with known vulnerabilities.

Given an app directory and a manifest of expected findings (the documented sink
locations), scan the whole app and report recall (did we find the known bugs?),
plus every finding not matched to the manifest — which needs human triage and is
NOT automatically a false positive (it may be a real bug the manifest omits, the
lesson Ethiack's methodology stresses).

This is the honest scoreboard: numbers here come from real code, unlike the
self-authored unit corpora.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field

from crucible.evals.scoring import Label, Score, score_findings
from crucible.schema.finding import Finding
from crucible.substrate.candidates import taint_candidates


@dataclass
class RealworldResult:
    score: Score
    matched: list[Finding] = field(default_factory=list)
    unmatched: list[Finding] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "score": self.score.to_dict(),
            "matched": len(self.matched),
            "unmatched_needs_triage": len(self.unmatched),
        }


def load_manifest(path: str) -> list[Label]:
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    return [
        Label(path=e["path"], start_line=e["line"], end_line=e.get("end_line"))
        for e in data.get("expected", [])
    ]


def measure_dir(app_dir: str, labels: list[Label]) -> RealworldResult:
    """Scan ``app_dir`` and score against ``labels`` (expected sink locations)."""
    findings = taint_candidates(app_dir)
    # Normalize prediction paths to be relative to app_dir so they line up with
    # the manifest's relative paths.
    for f in findings:
        if os.path.isabs(f.location.path) or f.location.path.startswith(app_dir):
            f.location.path = os.path.relpath(f.location.path, app_dir)

    matched: list[Finding] = []
    unmatched: list[Finding] = []
    for f in findings:
        if any(lbl.contains(f.location.path, f.location.start_line) for lbl in labels):
            matched.append(f)
        else:
            unmatched.append(f)
    score = score_findings(findings, labels)
    return RealworldResult(score=score, matched=matched, unmatched=unmatched)
