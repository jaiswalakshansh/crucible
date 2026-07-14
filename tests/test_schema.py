"""Tests for the core data contracts and the fail-open ladder semantics."""

from crucible.schema.finding import (
    ConfirmationStatus,
    Finding,
    Location,
    Severity,
    StabilityScore,
    ValidationGate,
    ValidationVerdict,
)
from crucible.schema.sarif import build_sarif
from crucible.schema.state import AnalysisEntry, FileRecord, ScanState
from crucible.validators.ladder import Gate, ValidationLadder


def _finding(rule="crucible.sql-injection", path="app/db.py", line=10) -> Finding:
    return Finding(
        rule_id=rule,
        message="untrusted input reaches query",
        severity=Severity.HIGH,
        location=Location(path=path, start_line=line),
        source="opengrep",
        cwe="CWE-89",
    )


def test_finding_sarif_round_trip_preserves_identity():
    f = _finding()
    result = f.to_sarif_result()
    parsed = Finding.from_sarif_result(result, source="opengrep")
    assert parsed.rule_id == f.rule_id
    assert parsed.location.path == f.location.path
    assert parsed.location.start_line == f.location.start_line


def test_finding_carries_honesty_signals():
    f = _finding()
    assert f.confirmation is ConfirmationStatus.SUSPECTED  # never "proven" by default
    assert f.stability.measured is False  # single run => stability unmeasured
    props = f.to_sarif_result()["properties"]
    assert props["crucible/confirmation"] == "suspected"
    assert props["crucible/stability"]["measured"] is False


def test_stability_score_ratio():
    s = StabilityScore(confirmed_runs=4, total_runs=5)
    assert s.ratio == 0.8
    assert s.measured is True


def test_filerecord_merge_is_idempotent():
    rec = FileRecord(path="app/db.py")
    assert rec.merge_findings([_finding(), _finding()]) == 1  # same fingerprint => 1
    assert rec.merge_findings([_finding()]) == 0  # rerun adds nothing
    assert len(rec.findings) == 1


def test_filerecord_resumability_check():
    rec = FileRecord(path="app/db.py", blob_sha="abc")
    rec.record_pass(AnalysisEntry(stage="recon", run_id="r1", blob_sha="abc"))
    assert rec.already_analyzed("recon", "abc") is True
    assert rec.already_analyzed("recon", "def") is False  # content changed => rerun
    assert rec.already_analyzed("hunt", "abc") is False


def test_scanstate_aggregates_findings():
    state = ScanState(run_id="r1", root=".")
    state.record_for("app/db.py").merge_findings([_finding()])
    state.record_for("app/api.py").merge_findings([_finding(path="app/api.py")])
    assert len(state.all_findings) == 2


def test_sarif_document_shape():
    doc = build_sarif([_finding()])
    assert doc["version"] == "2.1.0"
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "Crucible"
    assert len(run["results"]) == 1
    assert run["results"][0]["ruleIndex"] == 0


# --- Ladder fail-open semantics -------------------------------------------------

class _PassGate(Gate):
    gate_id = ValidationGate.DETERMINISTIC_PREFILTER

    def evaluate(self, finding):
        return ValidationVerdict(gate=self.gate_id, passed=True)


class _RefuteGate(Gate):
    gate_id = ValidationGate.ADVERSARIAL_DISPROOF

    def evaluate(self, finding):
        return ValidationVerdict(gate=self.gate_id, passed=False, detail="disproved")


class _ExplodingGate(Gate):
    gate_id = ValidationGate.REACHABILITY_AUDIT

    def evaluate(self, finding):
        raise RuntimeError("tool crashed")


class _PoCPassGate(Gate):
    gate_id = ValidationGate.POC_SANDBOX

    def evaluate(self, finding):
        return ValidationVerdict(gate=self.gate_id, passed=True, detail="poc fired")


def test_ladder_refute_stops_and_marks_refuted():
    out = ValidationLadder([_PassGate(), _RefuteGate(), _PoCPassGate()]).run(_finding())
    assert out.confirmation is ConfirmationStatus.REFUTED
    # PoC gate must not have run after refutation
    assert all(v.gate is not ValidationGate.POC_SANDBOX for v in out.verdicts)


def test_ladder_is_fail_open_on_gate_error():
    out = ValidationLadder([_ExplodingGate()]).run(_finding())
    # A crashing gate retains the finding rather than dropping it.
    assert out.confirmation is ConfirmationStatus.INCONCLUSIVE
    assert out.verdicts[-1].failed_open is True


def test_ladder_confirms_only_on_fired_poc():
    out = ValidationLadder([_PassGate(), _PoCPassGate()]).run(_finding())
    assert out.confirmation is ConfirmationStatus.CONFIRMED
