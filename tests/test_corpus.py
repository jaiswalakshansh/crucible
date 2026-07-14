"""Measure the taint analyzer on the labeled corpus and assert the score.

This is a functional check, not an independent accuracy benchmark: the rule packs
and the corpus were authored together, so a high score is expected and does NOT
demonstrate real-world accuracy (see the manifest's note and STATUS.md). Its value
is as a regression guard — if a change breaks a labeled flow or introduces a false
positive on the safe cases, this test fails.
"""

import os

from crucible.evals.harness import load_fixture, run_eval
from crucible.substrate.candidates import analyze_file

CORPUS = os.path.join(
    os.path.dirname(__file__), "..", "evals", "fixtures", "taint_corpus"
)


def test_corpus_scores_are_reported_and_perfect_on_this_set():
    cases = load_fixture(CORPUS)
    result = run_eval(cases, analyze_file, root=CORPUS)
    s = result.overall
    # On this self-authored set the analyzer is expected to reproduce every
    # labeled flow and flag none of the safe files.
    assert s.fn == 0, f"missed a labeled flow: {result.to_dict()}"
    assert s.fp == 0, f"flagged a safe file: {result.to_dict()}"
    assert s.precision == 1.0
    assert s.recall == 1.0
    # Print so the number is visible in test output (-s).
    print("taint corpus score:", result.overall.to_dict())


def test_corpus_has_both_vulnerable_and_safe_cases():
    cases = load_fixture(CORPUS)
    vuln = [c for c in cases if c.labels]
    safe = [c for c in cases if not c.labels]
    assert len(vuln) >= 3
    assert len(safe) >= 3  # precision must be tested, not just recall
