"""Verify the end-to-end pipeline composes recon -> ladder -> consensus."""

import json
import sys

from crucible.backends.fake import FakeBackend
from crucible.harness import Pipeline
from crucible.sandbox import LocalSubprocessExecutor
from crucible.schema.finding import ConfirmationStatus, Finding, Location, Severity
from crucible.schema.sarif import build_sarif
from crucible.validators.gates import AdversarialGate, PoCGate
from crucible.validators.ladder import ValidationLadder


def _candidate(target: str) -> list[Finding]:
    f = Finding(
        rule_id="crucible.sql-injection",
        message="untrusted input reaches query",
        severity=Severity.HIGH,
        location=Location(path=f"{target}/db.py", start_line=4),
        cwe="CWE-89",
    )
    f.evidence["code"] = "db.execute(user_input)"
    f.evidence["poc"] = {
        "files": {"poc.py": "raise SystemExit(0)"},
        "entrypoint": [sys.executable, "poc.py"],
    }
    return [f]


def _ladder() -> ValidationLadder:
    survive = FakeBackend(
        matcher=lambda _u: json.dumps({"refuted": False, "reason": "reaches sink"})
    )
    return ValidationLadder([AdversarialGate(survive), PoCGate(LocalSubprocessExecutor())])


def test_pipeline_confirms_a_real_finding_end_to_end():
    pipe = Pipeline(candidate_source=_candidate, ladder=_ladder())
    findings = pipe.scan("app")
    assert len(findings) == 1
    assert findings[0].confirmation is ConfirmationStatus.CONFIRMED


def test_pipeline_attaches_stability_over_multiple_runs():
    pipe = Pipeline(candidate_source=_candidate, ladder=_ladder())
    findings = pipe.scan("app", runs=3)
    assert findings[0].stability.total_runs == 3
    assert findings[0].stability.confirmed_runs == 3
    assert findings[0].stability.measured is True


def test_pipeline_output_serializes_to_sarif():
    pipe = Pipeline(candidate_source=_candidate, ladder=_ladder())
    doc = build_sarif(pipe.scan("app"))
    result = doc["runs"][0]["results"][0]
    assert result["properties"]["crucible/confirmation"] == "confirmed"


def test_pipeline_rejects_zero_runs():
    pipe = Pipeline(candidate_source=_candidate, ladder=_ladder())
    try:
        pipe.scan("app", runs=0)
    except ValueError:
        return
    raise AssertionError("expected ValueError for runs=0")
