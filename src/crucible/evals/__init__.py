"""Evaluation harness.

The project rule is that no component ships a quality claim without a measured
number. This package produces those numbers. Two parts:

- ``scoring``  — precision/recall/F1 from a set of predicted findings against
  labeled ground truth. Pure arithmetic; fully unit-tested.
- ``harness``  — runs a scan function over a set of labeled cases and scores the
  result. Takes the scan function as an argument so it can be driven by a real
  pipeline or, in tests, by a deterministic stub.

Important: this repo ships only a tiny synthetic fixture set to exercise the
scoring path. It is NOT the OWASP Benchmark and proves nothing about accuracy.
Running against OWASP (the target in PLAN.md) is not done here.
"""

from crucible.evals.scoring import Score, score_findings
from crucible.evals.harness import Case, EvalResult, run_eval

__all__ = ["Score", "score_findings", "Case", "EvalResult", "run_eval"]
