"""Verify consensus bookkeeping: stability counts and threshold filtering."""

from crucible.schema.finding import Finding, Location, Severity
from crucible.validators.consensus import apply_threshold, merge_runs


def _f(rule="r", path="a.py", line=1) -> Finding:
    return Finding(
        rule_id=rule,
        message="m",
        severity=Severity.MEDIUM,
        location=Location(path=path, start_line=line),
    )


def test_merge_counts_runs_per_fingerprint():
    runs = [
        [_f(line=1), _f(line=2)],  # run 1: fp@1, fp@2
        [_f(line=1)],              # run 2: fp@1
        [_f(line=1), _f(line=3)],  # run 3: fp@1, fp@3
    ]
    merged = {f.fingerprint: f for f in merge_runs(runs)}
    assert len(merged) == 3
    at1 = merged["r::a.py::1"]
    assert at1.stability.confirmed_runs == 3
    assert at1.stability.total_runs == 3
    assert at1.stability.ratio == 1.0
    assert merged["r::a.py::2"].stability.confirmed_runs == 1
    assert merged["r::a.py::3"].stability.confirmed_runs == 1


def test_merge_counts_each_fingerprint_once_per_run():
    # A duplicate within a single run must not inflate the count.
    runs = [[_f(line=1), _f(line=1)], [_f(line=1)]]
    merged = merge_runs(runs)
    assert len(merged) == 1
    assert merged[0].stability.confirmed_runs == 2  # two runs, not three


def test_merge_preserves_first_seen_order():
    runs = [[_f(line=5), _f(line=1)], [_f(line=3)]]
    order = [f.location.start_line for f in merge_runs(runs)]
    assert order == [5, 1, 3]


def test_threshold_keeps_majority_only():
    runs = [
        [_f(line=1), _f(line=2)],
        [_f(line=1)],
        [_f(line=1)],
    ]
    merged = merge_runs(runs)
    kept = apply_threshold(merged, min_ratio=0.5)
    lines = {f.location.start_line for f in kept}
    assert lines == {1}  # fp@1 in 3/3, fp@2 in 1/3 (<0.5) dropped


def test_threshold_boundary_is_inclusive():
    runs = [[_f(line=1)], [_f(line=2)]]  # each fp seen in 1/2 = 0.5
    kept = apply_threshold(merge_runs(runs), min_ratio=0.5)
    assert len(kept) == 2  # >= is inclusive
