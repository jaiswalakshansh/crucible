"""Eval harness: run a scan function over labeled cases and score it.

The scan function is injected (``Callable[[str], list[Finding]]``) so the same
harness can drive the real pipeline or, in tests, a deterministic stub. This
keeps the harness itself verifiable without a model or external tools.

A fixture set is a directory containing ``manifest.json`` of the form:

    {
      "cases": [
        {"path": "sqli.py", "labels": [{"start_line": 4, "end_line": 4}]},
        {"path": "safe.py", "labels": []}
      ]
    }

Paths are relative to the fixture directory.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Callable

from crucible.evals.scoring import Label, Score, score_findings
from crucible.schema.finding import Finding

ScanFn = Callable[[str], list[Finding]]


@dataclass
class Case:
    path: str
    labels: list[Label] = field(default_factory=list)


@dataclass
class EvalResult:
    overall: Score
    per_case: dict[str, Score]

    def to_dict(self) -> dict:
        return {
            "overall": self.overall.to_dict(),
            "per_case": {k: v.to_dict() for k, v in self.per_case.items()},
        }


def load_fixture(fixture_dir: str) -> list[Case]:
    with open(os.path.join(fixture_dir, "manifest.json"), encoding="utf-8") as fh:
        manifest = json.load(fh)
    cases: list[Case] = []
    for entry in manifest["cases"]:
        labels = [
            Label(
                path=entry["path"],
                start_line=lbl["start_line"],
                end_line=lbl.get("end_line"),
            )
            for lbl in entry.get("labels", [])
        ]
        cases.append(Case(path=entry["path"], labels=labels))
    return cases


def run_eval(cases: list[Case], scan_fn: ScanFn, *, root: str = "") -> EvalResult:
    """Run ``scan_fn`` on each case and aggregate scores.

    Aggregation sums tp/fp/fn across cases (micro-average) — a documented choice;
    a macro-average would weight each case equally regardless of size.
    """
    per_case: dict[str, Score] = {}
    tot_tp = tot_fp = tot_fn = 0
    for case in cases:
        target = os.path.join(root, case.path) if root else case.path
        preds = scan_fn(target)
        # Normalize prediction paths to be relative to ``root`` so they line up
        # with the manifest's relative label paths.
        if root:
            for p in preds:
                if os.path.isabs(p.location.path) or p.location.path.startswith(root):
                    p.location.path = os.path.relpath(p.location.path, root)
        s = score_findings(preds, case.labels)
        per_case[case.path] = s
        tot_tp += s.tp
        tot_fp += s.fp
        tot_fn += s.fn
    return EvalResult(
        overall=Score(tp=tot_tp, fp=tot_fp, fn=tot_fn), per_case=per_case
    )
