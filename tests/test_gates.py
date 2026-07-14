"""Verify gate control flow with a scripted backend.

These tests check orchestration only: verdict mapping, evidence recording, and
fail-open behavior on malformed output and backend errors. They do NOT measure
the quality of any model's judgment.
"""

import json

from crucible.backends.base import LLMBackend
from crucible.backends.fake import FakeBackend
from crucible.schema.finding import (
    ConfirmationStatus,
    Finding,
    Location,
    Severity,
    ValidationGate,
)
from crucible.validators.gates import AdversarialGate, PrefilterGate, ReachabilityGate
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


# --- PrefilterGate (deterministic) ---------------------------------------------

def test_prefilter_reachable_passes():
    v = PrefilterGate().evaluate(_finding(taint={"reachable": True}))
    assert v.passed is True
    assert v.failed_open is False


def test_prefilter_unreachable_soft_deprioritizes_not_drops():
    f = _finding(taint={"reachable": False})
    v = PrefilterGate().evaluate(f)
    assert v.passed is True  # soft mode never rejects
    assert f.evidence.get("deprioritized") is True


def test_prefilter_unreachable_hard_refutes():
    v = PrefilterGate(hard=True).evaluate(_finding(taint={"reachable": False}))
    assert v.passed is False


def test_prefilter_no_evidence_retains_without_failopen():
    v = PrefilterGate().evaluate(_finding())
    assert v.passed is True
    assert v.failed_open is False  # missing data is not a gate error


# --- AdversarialGate (LLM, scripted) -------------------------------------------

def test_adversarial_refute_marks_passed_false():
    backend = FakeBackend([json.dumps({"refuted": True, "reason": "input is a constant"})])
    v = AdversarialGate(backend).evaluate(_finding(code="x = 1"))
    assert v.passed is False
    assert "refuted" in v.detail


def test_adversarial_survive_marks_passed_true_and_records_evidence():
    backend = FakeBackend([json.dumps({"refuted": False, "reason": "reaches sink"})])
    f = _finding(code="db.execute(user_input)")
    v = AdversarialGate(backend).evaluate(f)
    assert v.passed is True
    assert "fake-model" in f.evidence["adversarial"]


def test_adversarial_malformed_json_is_fail_open():
    backend = FakeBackend(["not json at all"])
    v = AdversarialGate(backend).evaluate(_finding())
    assert v.failed_open is True
    assert v.passed is True  # retained, not dropped


def test_adversarial_backend_error_is_fail_open():
    class Boom(LLMBackend):
        name = "boom"

        def complete(self, messages, *, json_mode=False, temperature=0.0, max_tokens=None):
            raise RuntimeError("network down")

    v = AdversarialGate(Boom()).evaluate(_finding())
    assert v.failed_open is True
    assert v.passed is True


def test_adversarial_prompt_includes_code_and_location():
    backend = FakeBackend([json.dumps({"refuted": False, "reason": "ok"})])
    AdversarialGate(backend).evaluate(_finding(code="SENTINEL_CODE"))
    user_msg = next(m.content for m in backend.calls[0] if m.role == "user")
    assert "SENTINEL_CODE" in user_msg
    assert "app/db.py:10" in user_msg


# --- ReachabilityGate (LLM, scripted) ------------------------------------------

def test_reachability_true_passes():
    backend = FakeBackend([json.dumps({"reachable": True, "reason": "direct path"})])
    v = ReachabilityGate(backend).evaluate(_finding())
    assert v.passed is True


def test_reachability_false_does_not_pass():
    backend = FakeBackend([json.dumps({"reachable": False, "reason": "sanitized"})])
    v = ReachabilityGate(backend).evaluate(_finding())
    assert v.passed is False


def test_reachability_malformed_is_fail_open():
    backend = FakeBackend(["{broken"])
    v = ReachabilityGate(backend).evaluate(_finding())
    assert v.failed_open is True


# --- Ladder composition with real gate classes ---------------------------------

def test_ladder_adversarial_refute_stops_before_later_gates():
    refuting = FakeBackend([json.dumps({"refuted": True, "reason": "constant"})])
    reach = FakeBackend([json.dumps({"reachable": True, "reason": "unused"})])
    ladder = ValidationLadder(
        [PrefilterGate(), AdversarialGate(refuting), ReachabilityGate(reach)]
    )
    out = ladder.run(_finding(taint={"reachable": True}, code="x=1"))
    assert out.confirmation is ConfirmationStatus.REFUTED
    # ReachabilityGate must not have run.
    assert all(
        v.gate is not ValidationGate.REACHABILITY_AUDIT for v in out.verdicts
    )
    # The reachability backend was never called.
    assert reach.calls == []
