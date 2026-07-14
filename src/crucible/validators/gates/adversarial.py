"""Gate 2 — adversarial disproof (LLM).

Prompts a model to try to *disprove* the claimed vulnerability. A finding the
model refutes is halted by the ladder (marked ``refuted``). This gate is intended
to run on a different model than the one that discovered the finding; it cannot
enforce that, so it records the model name it used in the verdict detail for
audit.

Fail-open: on a backend error or a response that cannot be parsed into the
expected schema, the gate returns ``failed_open=True`` and the finding is
retained. Only an explicit, well-formed ``{"refuted": true}`` refutes.

Expected response schema (JSON): ``{"refuted": bool, "reason": str}``.

Verification: control flow (refute / keep / malformed / backend-error) is tested
with a scripted backend. Judgment quality is not measured here.
"""

from __future__ import annotations

from crucible.backends.base import LLMBackend, LLMMessage
from crucible.schema.finding import Finding, ValidationGate, ValidationVerdict
from crucible.validators.ladder import Gate

_SYSTEM = (
    "You are a skeptical application-security reviewer. Your only job is to try to "
    "DISPROVE a claimed vulnerability. Assume it is a false positive until the "
    "evidence forces otherwise. Consider whether the input is actually "
    "attacker-controlled, whether a sanitizer neutralizes it, and whether the sink "
    "is actually dangerous in this context. If you cannot construct a plausible "
    "exploit path, the finding is refuted."
)


class AdversarialGate(Gate):
    gate_id = ValidationGate.ADVERSARIAL_DISPROOF

    def __init__(self, backend: LLMBackend) -> None:
        self.backend = backend

    def _build_prompt(self, finding: Finding) -> str:
        code = finding.evidence.get("code", "(source not provided)")
        return (
            f"Claimed finding: {finding.rule_id} ({finding.cwe or 'no CWE'})\n"
            f"Severity: {finding.severity.value}\n"
            f"Location: {finding.location.path}:{finding.location.start_line}\n"
            f"Message: {finding.message}\n\n"
            f"Code under review:\n{code}\n\n"
            'Respond as JSON: {"refuted": <true|false>, "reason": "<short>"}'
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

        if not isinstance(resp.parsed, dict) or "refuted" not in resp.parsed:
            return ValidationVerdict(
                gate=self.gate_id,
                passed=True,
                detail=f"unparseable verdict from {resp.model}, retained (fail-open)",
                failed_open=True,
            )

        reason = str(resp.parsed.get("reason", ""))[:500]
        finding.evidence.setdefault("adversarial", {})[resp.model] = resp.parsed
        if bool(resp.parsed["refuted"]):
            return ValidationVerdict(
                gate=self.gate_id,
                passed=False,
                detail=f"refuted by {resp.model}: {reason}",
            )
        return ValidationVerdict(
            gate=self.gate_id,
            passed=True,
            detail=f"survived disproof by {resp.model}: {reason}",
        )
