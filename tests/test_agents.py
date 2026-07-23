"""Verify semantic-agent orchestration with a scripted backend.

These check control flow only — prompt construction, JSON parsing, severity
mapping, fail-open. Detection quality is NOT tested (needs a real model); the
gated integration test in tests/integration covers a real run when a key is set.
"""

import json
import os

import pytest

from crucible.agents import SemanticVulnAgent, SeverityAgent, run_semantic_agents
from crucible.backends.base import LLMBackend
from crucible.backends.fake import FakeBackend
from crucible.schema.finding import ConfirmationStatus, Finding, Location, Severity
from crucible.skills import SkillRegistry

SKILLS_DIR = os.path.join(os.path.dirname(__file__), "..", "skills")


def _skill(name="broken-access-control"):
    return SkillRegistry.from_dir(SKILLS_DIR).get(name)


def _finding():
    return Finding(
        rule_id="crucible.broken-access-control", message="m", severity=Severity.HIGH,
        location=Location(path="a.py", start_line=1), cwe="CWE-639",
    )


def test_agent_rejects_non_semantic_skill():
    taint_skill = SkillRegistry.from_dir(SKILLS_DIR).get("sql-injection")
    with pytest.raises(ValueError):
        SemanticVulnAgent(taint_skill, FakeBackend([]))


def test_agent_produces_suspected_finding():
    backend = FakeBackend([json.dumps(
        {"findings": [{"line": 5, "severity": "high", "reason": "no ownership check"}]}
    )])
    findings = SemanticVulnAgent(_skill(), backend).analyze("code\n", "app.py")
    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "crucible.broken-access-control"
    assert f.confirmation is ConfirmationStatus.SUSPECTED  # agents never confirm
    assert f.location.start_line == 5
    assert f.evidence["agent"]["skill"] == "broken-access-control"


def test_agent_prompt_includes_skill_methodology():
    backend = FakeBackend([json.dumps({"findings": []})])
    SemanticVulnAgent(_skill(), backend).analyze("code", "app.py")
    system = backend.calls[0][0].content
    assert "broken-access-control" in system
    assert "authorization" in system.lower() or "ownership" in system.lower()


def test_agent_fail_open_on_malformed_json():
    assert SemanticVulnAgent(_skill(), FakeBackend(["not json"])).analyze("x") == []


def test_agent_fail_open_on_backend_error():
    class Boom(LLMBackend):
        name = "boom"

        def complete(self, messages, *, json_mode=False, temperature=0.0, max_tokens=None):
            raise RuntimeError("down")

    assert SemanticVulnAgent(_skill(), Boom()).analyze("x") == []


def test_agent_skips_items_without_line():
    backend = FakeBackend([json.dumps({"findings": [{"severity": "high"}, {"line": 3}]})])
    findings = SemanticVulnAgent(_skill(), backend).analyze("code")
    assert len(findings) == 1  # the item missing a line is dropped
    assert findings[0].location.start_line == 3


def test_run_semantic_agents_covers_all_semantic_skills():
    reg = SkillRegistry.from_dir(SKILLS_DIR)
    semantic = reg.by_technique("semantic")
    # each agent returns one finding at line 1
    backend = FakeBackend(
        matcher=lambda _u: json.dumps({"findings": [{"line": 1, "severity": "low", "reason": "x"}]})
    )
    findings = run_semantic_agents("code", "app.py", semantic, backend)
    assert len(findings) == len(semantic) >= 4


def test_severity_agent_annotates_finding():
    backend = FakeBackend([json.dumps(
        {"cvss_score": 8.1, "severity": "high", "vector": "CVSS:3.1/AV:N", "rationale": "idor"}
    )])
    f = _finding()
    result = SeverityAgent(backend).score(f, "code")
    assert result["cvss_score"] == 8.1
    assert f.evidence["severity_assessment"]["severity"] == "high"


def test_severity_agent_fail_open():
    f = _finding()
    assert SeverityAgent(FakeBackend(["bad"])).score(f, "code") is None
    assert "severity_assessment" not in f.evidence
