"""Gate 1 — deterministic reachability pre-filter (no LLM).

Design decision and its justification:

By default this gate does NOT reject findings. It reads any taint/reachability
evidence already attached to the finding (e.g. from Opengrep taint mode) and uses
it only to *deprioritize*, not to drop. The reason is that static taint analysis
is known to be incomplete — the market research recorded a case where naively
gating on a static-analysis tool (CodeQL via MCP) reduced detection accuracy from
44% to 31%. Hard-rejecting on an incomplete reachability signal would discard true
positives. So the safe default is: annotate, keep.

An optional ``hard`` mode is provided for callers who have a high-precision
reachability oracle and accept the recall tradeoff; in that mode an explicit
"unreachable" verdict refutes the finding. Default is soft.

Evidence contract: ``finding.evidence["taint"]`` may contain ``{"reachable": bool}``.
- reachable True  -> pass, no change.
- reachable False -> soft mode: pass, mark ``evidence["deprioritized"] = True``.
                     hard mode: refute (passed=False).
- absent          -> pass unchanged (undetermined; not an error, not fail-open).
"""

from __future__ import annotations

from crucible.schema.finding import Finding, ValidationGate, ValidationVerdict
from crucible.validators.ladder import Gate


class PrefilterGate(Gate):
    gate_id = ValidationGate.DETERMINISTIC_PREFILTER

    def __init__(self, *, hard: bool = False) -> None:
        self.hard = hard

    def evaluate(self, finding: Finding) -> ValidationVerdict:
        taint = finding.evidence.get("taint")
        if not isinstance(taint, dict) or "reachable" not in taint:
            return ValidationVerdict(
                gate=self.gate_id,
                passed=True,
                detail="no reachability evidence; undetermined, retained",
            )
        reachable = bool(taint["reachable"])
        if reachable:
            return ValidationVerdict(
                gate=self.gate_id, passed=True, detail="reachable path present"
            )
        # Not reachable per static evidence.
        if self.hard:
            return ValidationVerdict(
                gate=self.gate_id,
                passed=False,
                detail="static evidence: no reachable source->sink path (hard mode)",
            )
        finding.evidence["deprioritized"] = True
        return ValidationVerdict(
            gate=self.gate_id,
            passed=True,
            detail="static evidence suggests unreachable; deprioritized, not dropped",
        )
