"""CVSS-style severity agent.

Ethiack's evaluation methodology treats severity (a CVSS-based score) as a
first-class metric alongside precision/recall. This agent asks a model to assess a
finding's impact and returns a normalized score. It annotates a finding's evidence;
it does not change confirmation status. Fail-open: on error/malformed output it
returns None and the finding keeps its detector-assigned severity.
"""

from __future__ import annotations

from crucible.backends.base import LLMBackend, LLMMessage
from crucible.schema.finding import Finding

_SYSTEM = (
    "You are a vulnerability-severity assessor. Given a finding and its code, "
    "estimate CVSS v3.1 base severity. Be conservative and concrete."
)


class SeverityAgent:
    def __init__(self, backend: LLMBackend) -> None:
        self.backend = backend

    def score(self, finding: Finding, code: str = "") -> dict | None:
        prompt = (
            f"Finding: {finding.rule_id} ({finding.cwe or 'no CWE'}) at "
            f"{finding.location.path}:{finding.location.start_line}\n"
            f"Message: {finding.message}\n\n"
            f"Code:\n{code}\n\n"
            'Respond as JSON: {"cvss_score": <0.0-10.0>, '
            '"severity": "critical|high|medium|low|none", "vector": "<CVSS vector>", '
            '"rationale": "<short>"}'
        )
        try:
            resp = self.backend.complete(
                [LLMMessage("system", _SYSTEM), LLMMessage("user", prompt)],
                json_mode=True,
            )
        except Exception:
            return None
        if not isinstance(resp.parsed, dict) or "cvss_score" not in resp.parsed:
            return None
        result = {
            "cvss_score": resp.parsed.get("cvss_score"),
            "severity": resp.parsed.get("severity"),
            "vector": resp.parsed.get("vector"),
            "rationale": str(resp.parsed.get("rationale", ""))[:500],
            "model": resp.model,
        }
        finding.evidence["severity_assessment"] = result
        return result
