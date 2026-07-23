"""Agent that finds a semantic vulnerability class, driven by a skill.

The agent turns a semantic ``SKILL.md`` into a review prompt, runs it against a
backend over a code file, and returns findings. It is deliberately conservative:
findings are ``suspected`` and carry the model's reasoning; nothing is confirmed.
On any backend error or unparseable output it returns no findings (fail-open — it
never fabricates a finding, and never crashes the pipeline).
"""

from __future__ import annotations

from crucible.backends.base import LLMBackend, LLMMessage
from crucible.schema.finding import (
    ConfirmationStatus,
    Finding,
    Location,
    Severity,
)
from crucible.skills.loader import Skill

_SEVERITY = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
}


class SemanticVulnAgent:
    def __init__(self, skill: Skill, backend: LLMBackend) -> None:
        if skill.technique != "semantic":
            raise ValueError(f"skill {skill.name!r} is not a semantic skill")
        self.skill = skill
        self.backend = backend

    def _system(self) -> str:
        return (
            f"You are a security reviewer looking ONLY for {self.skill.name} "
            f"({self.skill.cwe}). Use this methodology:\n\n{self.skill.body}\n\n"
            "Report only genuine instances with concrete reasoning. If there are "
            "none, return an empty list. Do not report other vulnerability classes."
        )

    def _user(self, code: str, path: str) -> str:
        return (
            f"File: {path}\n\n{code}\n\n"
            'Respond as JSON: {"findings": [{"line": <int>, "severity": '
            '"high|medium|low", "reason": "<short>"}]}'
        )

    def analyze(self, code: str, path: str = "<memory>") -> list[Finding]:
        messages = [
            LLMMessage("system", self._system()),
            LLMMessage("user", self._user(code, path)),
        ]
        try:
            resp = self.backend.complete(messages, json_mode=True)
        except Exception:
            return []  # fail-open: no fabricated findings, no crash
        if not isinstance(resp.parsed, dict):
            return []
        items = resp.parsed.get("findings")
        if not isinstance(items, list):
            return []

        findings: list[Finding] = []
        for item in items:
            if not isinstance(item, dict) or "line" not in item:
                continue
            try:
                line = int(item["line"])
            except (TypeError, ValueError):
                continue
            severity = _SEVERITY.get(
                str(item.get("severity", "")).lower(),
                _SEVERITY.get(self.skill.severity or "medium", Severity.MEDIUM),
            )
            finding = Finding(
                rule_id=self.skill.rule_id or f"crucible.{self.skill.name}",
                message=str(item.get("reason", self.skill.description))[:500],
                severity=severity,
                location=Location(path=path, start_line=line),
                source=f"agent:{self.skill.name}",
                cwe=self.skill.cwe,
                confirmation=ConfirmationStatus.SUSPECTED,
            )
            finding.evidence["agent"] = {
                "skill": self.skill.name,
                "model": resp.model,
                "reason": str(item.get("reason", "")),
            }
            findings.append(finding)
        return findings


def run_semantic_agents(
    code: str,
    path: str,
    skills: list[Skill],
    backend: LLMBackend,
) -> list[Finding]:
    """Run every semantic skill's agent over ``code`` and collect findings."""
    out: list[Finding] = []
    for skill in skills:
        if skill.technique != "semantic":
            continue
        out.extend(SemanticVulnAgent(skill, backend).analyze(code, path))
    return out
