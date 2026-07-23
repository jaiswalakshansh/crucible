"""Load and index ``SKILL.md`` files.

Frontmatter schema (YAML between ``---`` fences):

    name: sql-injection            # unique slug
    description: <one line>
    rule_id: crucible.sql-injection  # links to detector findings (optional)
    cwe: CWE-89
    severity: high | medium | low
    technique: taint | pattern | semantic
    activation: ["scan for sqli", ...]   # optional trigger phrases

The rest of the file (after the second ``---``) is the methodology body.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any

import yaml

from crucible.schema.finding import Finding


@dataclass
class Skill:
    name: str
    description: str
    body: str
    path: str
    rule_id: str | None = None
    cwe: str | None = None
    severity: str | None = None
    technique: str | None = None
    activation: list[str] = field(default_factory=list)

    def matches(self, finding: Finding) -> bool:
        if self.rule_id and self.rule_id == finding.rule_id:
            return True
        if self.cwe and finding.cwe and self.cwe == finding.cwe:
            return True
        return False


class SkillParseError(ValueError):
    pass


def parse_skill(text: str, path: str = "<memory>") -> Skill:
    if not text.startswith("---"):
        raise SkillParseError(f"{path}: missing YAML frontmatter")
    parts = text.split("---", 2)
    if len(parts) < 3:
        raise SkillParseError(f"{path}: unterminated frontmatter")
    try:
        meta: Any = yaml.safe_load(parts[1]) or {}
    except yaml.YAMLError as exc:
        raise SkillParseError(f"{path}: invalid YAML frontmatter: {exc}") from exc
    if not isinstance(meta, dict) or "name" not in meta:
        raise SkillParseError(f"{path}: frontmatter must be a mapping with a 'name'")
    activation = meta.get("activation") or []
    if isinstance(activation, str):
        activation = [activation]
    return Skill(
        name=str(meta["name"]),
        description=str(meta.get("description", "")).strip(),
        body=parts[2].strip(),
        path=path,
        rule_id=meta.get("rule_id"),
        cwe=meta.get("cwe"),
        severity=meta.get("severity"),
        technique=meta.get("technique"),
        activation=[str(a) for a in activation],
    )


def load_skills(root: str) -> list[Skill]:
    """Load every ``SKILL.md`` under ``root`` (recursively)."""
    skills: list[Skill] = []
    for dirpath, _dirnames, filenames in os.walk(root):
        for name in filenames:
            if name == "SKILL.md":
                path = os.path.join(dirpath, name)
                with open(path, encoding="utf-8") as fh:
                    skills.append(parse_skill(fh.read(), path))
    return skills


class SkillRegistry:
    def __init__(self, skills: list[Skill] | None = None) -> None:
        self._skills: list[Skill] = []
        self._by_name: dict[str, Skill] = {}
        for s in skills or []:
            self.add(s)

    @classmethod
    def from_dir(cls, root: str) -> "SkillRegistry":
        return cls(load_skills(root))

    def add(self, skill: Skill) -> None:
        if skill.name in self._by_name:
            raise SkillParseError(f"duplicate skill name: {skill.name}")
        self._skills.append(skill)
        self._by_name[skill.name] = skill

    def __len__(self) -> int:
        return len(self._skills)

    def get(self, name: str) -> Skill | None:
        return self._by_name.get(name)

    @property
    def names(self) -> list[str]:
        return sorted(self._by_name)

    def for_finding(self, finding: Finding) -> list[Skill]:
        """Skills relevant to a finding (matched by rule_id or CWE)."""
        return [s for s in self._skills if s.matches(finding)]

    def by_technique(self, technique: str) -> list[Skill]:
        return [s for s in self._skills if s.technique == technique]
