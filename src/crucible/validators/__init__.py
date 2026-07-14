"""L3 — the validation ladder (Crucible's moat).

Every candidate climbs five gates, cheapest -> strongest. A finding is *reported*
only if it survives to the gate appropriate for its severity, and *auto-confirmed*
only if it produces a firing PoC. Two invariants hold across every gate:

1. **Fail-open** — a gate that errors or times out retains the finding
   (``ConfirmationStatus.INCONCLUSIVE``); we never drop a possible true positive
   because a tool broke.
2. **Adversarial** where it counts — the disproof gate uses a *different model*
   than discovery, because putting two models in deliberate disagreement beats
   any amount of single-agent prompting.

Phase 0 ships the ladder scaffold and the fail-open contract; individual gates
are implemented and A/B-measured in Phase 1+.
"""

from crucible.validators.ladder import ValidationLadder, Gate

__all__ = ["ValidationLadder", "Gate"]
