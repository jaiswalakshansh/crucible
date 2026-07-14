"""Gate 3 — reachability audit (LLM).

Asks a model to judge whether attacker-controlled input can actually reach the
sink (end-to-end reachability plus per-hop sanitization). A finding judged
unreachable does not pass; the ladder stops climbing and leaves it ``suspected``
(it is neither confirmed nor formally refuted — we simply could not establish a
path). This is deliberately weaker than the adversarial gate's refutation.

Fail-open on backend error or unparseable output, same contract as the other LLM
gate.

Expected response schema (JSON): ``{"reachable": bool, "reason": str}``.

Verification: control flow tested with a scripted backend; judgment quality not
measured here.
"""

from __future__ import annotations

from crucible.backends.base import LLMBackend, LLMMessage
from crucible.schema.finding import Finding, ValidationGate, ValidationVerdict
from crucible.validators.ladder import Gate

_SYSTEM = (
    "You are a program-analysis reviewer. Determine whether attacker-controlled "
    "input can reach the described sink. Check the end-to-end path: is the source "
    "genuinely external, does control flow actually connect source to sink, and is "
    "the taint neutralized by any sanitizer, encoder, or type coercion along the "
    "way? Answer only about reachability, not severity."
)


class ReachabilityGate(Gate):
    gate_id = ValidationGate.REACHABILITY_AUDIT

    def __init__(self, backend: LLMBackend) -> None:
        self.backend = backend

    def _build_prompt(self, finding: Finding) -> str:
        code = finding.evidence.get("code", "(source not provided)")
        path = finding.evidence.get("taint", {}).get("path", "(no taint path given)")
        return (
            f"Finding: {finding.rule_id} at "
            f"{finding.location.path}:{finding.location.start_line}\n"
            f"Reported taint path: {path}\n\n"
            f"Code under review:\n{code}\n\n"
            'Respond as JSON: {"reachable": <true|false>, "reason": "<short>"}'
        )

    def evaluate(self, finding: Finding) -> ValidationVerdict:
        messages = [
            LLMMessage("system", _SYSTEM),
            LLMMessage("user", self._build_prompt(finding)),
        ]
        try:
            resp = self.backend.complete(messages, json_mode=True)
        except Exception as exc:
            return ValidationVerdict(
                gate=self.gate_id,
                passed=True,
                detail=f"backend error, retained (fail-open): {exc}",
                failed_open=True,
            )

        if not isinstance(resp.parsed, dict) or "reachable" not in resp.parsed:
            return ValidationVerdict(
                gate=self.gate_id,
                passed=True,
                detail=f"unparseable verdict from {resp.model}, retained (fail-open)",
                failed_open=True,
            )

        reason = str(resp.parsed.get("reason", ""))[:500]
        finding.evidence.setdefault("reachability", {})[resp.model] = resp.parsed
        reachable = bool(resp.parsed["reachable"])
        return ValidationVerdict(
            gate=self.gate_id,
            passed=reachable,
            detail=(
                f"reachable per {resp.model}: {reason}"
                if reachable
                else f"not reachable per {resp.model}: {reason}"
            ),
        )
