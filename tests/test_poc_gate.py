"""Verify the PoC gate end-to-end with real execution, and its LLM-gen path."""

import json
import sys

from crucible.backends.fake import FakeBackend
from crucible.sandbox import LocalSubprocessExecutor
from crucible.schema.finding import (
    ConfirmationStatus,
    Finding,
    Location,
    Severity,
    ValidationGate,
)
from crucible.validators.gates import (
    AdversarialGate,
    PoCGate,
    PrefilterGate,
)
from crucible.validators.ladder import ValidationLadder


def _finding(**evidence) -> Finding:
    f = Finding(
        rule_id="crucible.sql-injection",
        message="untrusted input reaches query",
        severity=Severity.HIGH,
        location=Location(path="app/db.py", start_line=10),
        cwe="CWE-89",
    )
    f.evidence.update(evidence)
    return f


def _poc(exit_code: int) -> dict:
    return {
        "files": {"poc.py": f"raise SystemExit({exit_code})"},
        "entrypoint": [sys.executable, "poc.py"],
    }


def test_firing_poc_passes_gate():
    v = PoCGate(LocalSubprocessExecutor()).evaluate(_finding(poc=_poc(0)))
    assert v.passed is True
    assert v.failed_open is False


def test_nonfiring_poc_does_not_pass():
    v = PoCGate(LocalSubprocessExecutor()).evaluate(_finding(poc=_poc(1)))
    assert v.passed is False


def test_no_poc_is_fail_open():
    v = PoCGate(LocalSubprocessExecutor()).evaluate(_finding())
    assert v.failed_open is True
    assert v.passed is True  # retained, not dropped


def test_backend_generated_poc_executes_for_real():
    # The scripted backend "generates" a real PoC that then actually runs.
    spec = json.dumps(
        {"files": {"poc.py": "raise SystemExit(0)"}, "entrypoint": [sys.executable, "poc.py"]}
    )
    gate = PoCGate(LocalSubprocessExecutor(), backend=FakeBackend([spec]))
    v = gate.evaluate(_finding(code="db.execute(user_input)"))
    assert v.passed is True


def test_gate_records_run_evidence():
    f = _finding(poc=_poc(0))
    PoCGate(LocalSubprocessExecutor()).evaluate(f)
    assert f.evidence["poc_run"]["status"] == "ok"
    assert f.evidence["poc_run"]["exit_code"] == 0


def test_full_ladder_confirms_only_on_fired_poc():
    # Prefilter passes, adversarial keeps, PoC fires -> CONFIRMED.
    survive = FakeBackend([json.dumps({"refuted": False, "reason": "reaches sink"})])
    ladder = ValidationLadder(
        [
            PrefilterGate(),
            AdversarialGate(survive),
            PoCGate(LocalSubprocessExecutor()),
        ]
    )
    out = ladder.run(_finding(taint={"reachable": True}, code="x", poc=_poc(0)))
    assert out.confirmation is ConfirmationStatus.CONFIRMED


def test_full_ladder_marks_not_reproduced_when_poc_fails():
    survive = FakeBackend([json.dumps({"refuted": False, "reason": "ok"})])
    ladder = ValidationLadder(
        [AdversarialGate(survive), PoCGate(LocalSubprocessExecutor())]
    )
    out = ladder.run(_finding(code="x", poc=_poc(1)))
    assert out.confirmation is ConfirmationStatus.NOT_REPRODUCED
    assert any(v.gate is ValidationGate.POC_SANDBOX for v in out.verdicts)
