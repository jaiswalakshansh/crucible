"""Verify the skill loader and registry (structure and matching)."""

import os

import pytest

from crucible.schema.finding import Finding, Location, Severity
from crucible.skills import SkillRegistry, load_skills, parse_skill
from crucible.skills.loader import SkillParseError

SKILLS_DIR = os.path.join(os.path.dirname(__file__), "..", "skills")


def _finding(rule="crucible.sql-injection", cwe="CWE-89"):
    return Finding(
        rule_id=rule, message="m", severity=Severity.HIGH,
        location=Location(path="a.py", start_line=1), cwe=cwe,
    )


def test_parse_valid_skill():
    text = (
        "---\n"
        "name: demo\n"
        "description: a demo\n"
        "rule_id: crucible.demo\n"
        "cwe: CWE-1\n"
        "technique: taint\n"
        'activation: ["do a demo"]\n'
        "---\n"
        "# Demo\nbody here\n"
    )
    s = parse_skill(text)
    assert s.name == "demo"
    assert s.rule_id == "crucible.demo"
    assert s.technique == "taint"
    assert s.activation == ["do a demo"]
    assert "body here" in s.body


def test_parse_rejects_missing_frontmatter():
    with pytest.raises(SkillParseError):
        parse_skill("# no frontmatter\n")


def test_parse_rejects_frontmatter_without_name():
    with pytest.raises(SkillParseError):
        parse_skill("---\ndescription: x\n---\nbody\n")


# --- The shipped skill library --------------------------------------------------

def test_all_shipped_skills_load():
    skills = load_skills(SKILLS_DIR)
    assert len(skills) >= 14
    # every skill has the required fields
    for s in skills:
        assert s.name
        assert s.description
        assert s.body
        assert s.technique in ("taint", "pattern", "semantic")


def test_skill_names_are_unique():
    # SkillRegistry raises on duplicates, so construction is the assertion.
    reg = SkillRegistry.from_dir(SKILLS_DIR)
    assert len(reg) == len(reg.names)


def test_registry_matches_finding_by_rule_id():
    reg = SkillRegistry.from_dir(SKILLS_DIR)
    matched = reg.for_finding(_finding("crucible.sql-injection", "CWE-89"))
    assert any(s.name == "sql-injection" for s in matched)


def test_registry_matches_finding_by_cwe_when_rule_absent():
    reg = SkillRegistry.from_dir(SKILLS_DIR)
    # A finding with a CWE but an unknown rule id still matches by CWE.
    matched = reg.for_finding(_finding("crucible.unknown", "CWE-89"))
    assert any(s.cwe == "CWE-89" for s in matched)


def test_semantic_skills_present_for_track_d():
    reg = SkillRegistry.from_dir(SKILLS_DIR)
    semantic = {s.name for s in reg.by_technique("semantic")}
    assert {"broken-access-control", "auth-bypass", "csrf", "business-logic"} <= semantic


def test_every_detector_rule_has_a_skill():
    # Each taint/pattern rule_id we ship should have a matching skill (coverage guard).
    reg = SkillRegistry.from_dir(SKILLS_DIR)
    have = {s.rule_id for s in reg.by_technique("taint")}
    expected = {
        "crucible.sql-injection", "crucible.command-injection",
        "crucible.code-injection", "crucible.ssrf", "crucible.path-traversal",
        "crucible.ssti", "crucible.xxe", "crucible.insecure-deserialization",
        "crucible.open-redirect", "crucible.dom-xss",
        "crucible.insecure-llm-output-handling",
    }
    missing = expected - have
    assert not missing, f"taint classes without a skill: {missing}"
