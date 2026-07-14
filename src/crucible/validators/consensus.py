"""Consensus across repeated runs.

The market research and the self-consistency literature suggest majority voting
across independent runs reduces run-to-run variance in LLM outputs. This module
implements the mechanism; it does not by itself prove any variance reduction —
that would require measuring real runs, which this repo has not done.

What is implemented and tested here (tests/test_consensus.py) is the deterministic
bookkeeping: group findings by fingerprint across N runs, count how many runs
surfaced each, and attach a ``StabilityScore(confirmed_runs=k, total_runs=N)``.
An optional threshold filter drops findings seen in fewer than a chosen fraction
of runs.
"""

from __future__ import annotations

from crucible.schema.finding import Finding, StabilityScore


def merge_runs(runs: list[list[Finding]]) -> list[Finding]:
    """Merge N runs into one deduplicated list with stability scores.

    Findings are grouped by ``fingerprint``. The first-seen instance of each
    fingerprint is kept as representative and annotated with how many runs
    contained it. Order is stable: representatives appear in the order first
    encountered while scanning runs left-to-right.
    """
    total = len(runs)
    order: list[str] = []
    rep: dict[str, Finding] = {}
    counts: dict[str, int] = {}

    for run in runs:
        seen_this_run: set[str] = set()
        for f in run:
            fp = f.fingerprint
            if fp not in rep:
                rep[fp] = f
                order.append(fp)
                counts[fp] = 0
            # Count each fingerprint at most once per run.
            if fp not in seen_this_run:
                counts[fp] += 1
                seen_this_run.add(fp)

    out: list[Finding] = []
    for fp in order:
        f = rep[fp]
        f.stability = StabilityScore(confirmed_runs=counts[fp], total_runs=total)
        out.append(f)
    return out


def apply_threshold(findings: list[Finding], min_ratio: float) -> list[Finding]:
    """Keep only findings whose stability ratio is >= ``min_ratio``.

    ``min_ratio`` of 0.5 means "seen in a majority of runs". Callers decide the
    policy; nothing is dropped implicitly elsewhere.
    """
    return [f for f in findings if f.stability.ratio >= min_ratio]
