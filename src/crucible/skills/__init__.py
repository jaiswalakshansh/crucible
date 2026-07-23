"""Skills: per-vulnerability-class knowledge as ``SKILL.md`` files.

A skill is a markdown file with YAML frontmatter (name, cwe, rule_id, technique,
activation) and a body describing recon and verification steps. Deterministic
detectors produce a candidate finding; the matching skill tells an LLM gate (or a
semantic agent, for classes taint cannot find) how to confirm or refute it.

What is verifiable here: skills are well-formed and the registry loads and matches
them to findings (unit-tested). What is NOT verifiable here: whether a skill
actually improves an LLM's judgment — that needs a model and a benchmark.
"""

from crucible.skills.loader import Skill, SkillRegistry, load_skills, parse_skill

__all__ = ["Skill", "SkillRegistry", "load_skills", "parse_skill"]
