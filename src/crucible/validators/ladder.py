"""The ladder orchestrator.

A ``Gate`` takes a Finding and returns a ``ValidationVerdict``. The
``ValidationLadder`` runs gates in order, appends verdicts, and enforces the two
invariants (fail-open, stop-on-refute). Concrete gates land in Phase 1+; the
scaffold here fixes the contract and the fail-open semantics so every future gate
inherits them.
"""

from __future__ import annotations

import abc

from crucible.schema.finding import (
    ConfirmationStatus,
    Finding,
    ValidationGate,
    ValidationVerdict,
)


class Gate(abc.ABC):
    """One rung of the ladder."""

    gate_id: ValidationGate

    @abc.abstractmethod
    def evaluate(self, finding: Finding) -> ValidationVerdict:
        """Return a verdict. Implementations should NOT raise for expected
        tool failures — return ``failed_open=True`` instead so the ladder keeps
        the finding. Unexpected exceptions are caught by the ladder as fail-open."""
        raise NotImplementedError


class ValidationLadder:
    def __init__(self, gates: list[Gate]) -> None:
        self.gates = gates

    def run(self, finding: Finding) -> Finding:
        """Climb the ladder, mutating ``finding`` with verdicts and a final
        confirmation status. Stops early if a gate refutes the finding."""
        for gate in self.gates:
            try:
                verdict = gate.evaluate(finding)
            except Exception as exc:  # fail-open: keep the finding, mark inconclusive
                verdict = ValidationVerdict(
                    gate=gate.gate_id,
                    passed=True,
                    detail=f"gate error, retained (fail-open): {exc}",
                    failed_open=True,
                )
                finding.verdicts.append(verdict)
                finding.confirmation = ConfirmationStatus.INCONCLUSIVE
                continue

            finding.verdicts.append(verdict)

            if verdict.failed_open:
                finding.confirmation = ConfirmationStatus.INCONCLUSIVE
                continue
            if not verdict.passed:
                # A gate actively disproved the finding — stop climbing.
                if gate.gate_id is ValidationGate.ADVERSARIAL_DISPROOF:
                    finding.confirmation = ConfirmationStatus.REFUTED
                elif gate.gate_id is ValidationGate.POC_SANDBOX:
                    finding.confirmation = ConfirmationStatus.NOT_REPRODUCED
                else:
                    finding.confirmation = ConfirmationStatus.SUSPECTED
                return finding

            # Passing the PoC sandbox is the only deterministic proof.
            if gate.gate_id is ValidationGate.POC_SANDBOX:
                finding.confirmation = ConfirmationStatus.CONFIRMED

        return finding
