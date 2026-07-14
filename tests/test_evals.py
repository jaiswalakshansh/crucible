"""Verify scoring arithmetic and the eval harness against hand-computed values."""

import os

from crucible.evals.harness import load_fixture, run_eval
from crucible.evals.scoring import Label, Score, score_findings
from crucible.schema.finding import Finding, Location, Severity

FIXTURE_DIR = os.path.join(
    os.path.dirname(__file__), "..", "evals", "fixtures", "synthetic"
)


def _pred(path, line) -> Finding:
    return Finding(
        rule_id="r",
        message="m",
        severity=Severity.HIGH,
        location=Location(path=path, start_line=line),
    )


def test_score_arithmetic_is_correct():
    s = Score(tp=8, fp=2, fn=4)
    assert s.precision == 0.8            # 8/10
    assert round(s.recall, 4) == 0.6667  # 8/12
    assert round(s.f1, 4) == 0.7273


def test_score_zero_division_is_zero_not_error():
    s = Score(tp=0, fp=0, fn=0)
    assert s.precision == 0.0
    assert s.recall == 0.0
    assert s.f1 == 0.0


def test_true_positive_within_label_span():
    labels = [Label(path="a.py", start_line=4, end_line=6)]
    s = score_findings([_pred("a.py", 5)], labels)
    assert (s.tp, s.fp, s.fn) == (1, 0, 0)


def test_false_positive_when_no_label_matches():
    labels = [Label(path="a.py", start_line=4)]
    s = score_findings([_pred("a.py", 99)], labels)
    assert (s.tp, s.fp, s.fn) == (0, 1, 1)


def test_false_negative_when_label_unmatched():
    labels = [Label(path="a.py", start_line=4), Label(path="b.py", start_line=1)]
    s = score_findings([_pred("a.py", 4)], labels)
    assert (s.tp, s.fp, s.fn) == (1, 0, 1)


def test_duplicate_predictions_in_one_label_count_once():
    labels = [Label(path="a.py", start_line=4)]
    s = score_findings([_pred("a.py", 4), _pred("a.py", 4)], labels)
    assert (s.tp, s.fp, s.fn) == (1, 0, 0)


def test_harness_on_synthetic_fixture_with_oracle_scanner():
    """A perfect scan_fn on the synthetic fixture should yield precision=recall=1.

    This checks the harness plumbing, not any real detector.
    """
    cases = load_fixture(FIXTURE_DIR)

    def oracle(path: str) -> list[Finding]:
        # Emit the known sink only for the vulnerable fixture file.
        if path.endswith("sqli.py"):
            return [_pred("sqli.py", 4)]
        return []

    result = run_eval(cases, oracle)
    assert result.overall.tp == 1
    assert result.overall.fp == 0
    assert result.overall.fn == 0
    assert result.overall.precision == 1.0
    assert result.overall.recall == 1.0


def test_harness_counts_false_positive_from_noisy_scanner():
    cases = load_fixture(FIXTURE_DIR)

    def noisy(path: str) -> list[Finding]:
        # Flags the safe file too -> one false positive, plus the real one.
        if path.endswith("sqli.py"):
            return [_pred("sqli.py", 4)]
        return [_pred(os.path.basename(path), 3)]

    result = run_eval(cases, noisy)
    assert result.overall.tp == 1
    assert result.overall.fp == 1  # from safe.py
