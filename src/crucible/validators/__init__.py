"""L3 — the validation ladder.

Candidates pass through gates in order. A finding is reported only if it survives
to the gate appropriate for its severity, and set to ``confirmed`` only if a
proof-of-concept executes successfully (PoC gate, not yet implemented). Two
invariants hold across every gate and are unit-tested (see tests/test_gates.py
and tests/test_schema.py):

1. Fail-open — a gate that errors or times out retains the finding as
   ``ConfirmationStatus.INCONCLUSIVE`` rather than dropping it.
2. Stop-on-refute — a gate that actively disproves a finding halts the ladder.

The adversarial disproof gate is *intended* to run on a different model than
discovery; the gate records the model name it used so this is auditable, but the
gate cannot itself enforce that the caller passed a distinct model.

Status: the ladder orchestration and the Phase 1 gates' control flow are tested
with a scripted backend. The accuracy of LLM verdicts is not measured here.
"""

from crucible.validators.ladder import ValidationLadder, Gate

__all__ = ["ValidationLadder", "Gate"]
