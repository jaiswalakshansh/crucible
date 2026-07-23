"""Semantic-vulnerability agents.

Some classes — broken access control / IDOR, auth bypass, CSRF, business logic —
are not data-flow problems. No taint path or signature finds them; they require
reasoning about intent and whether a check exists. That reasoning is an LLM's job,
driven by the matching semantic ``SKILL.md``.

What is verifiable here (with a scripted backend): the agent builds a prompt from
the skill, parses the model's JSON into findings, maps severities, and fails open
on error/malformed output. What is NOT verifiable here: detection quality — that
needs a real model and a benchmark. Every finding an agent produces is reported as
``suspected`` with the model's reasoning; agents never mark anything ``confirmed``.
"""

from crucible.agents.semantic import SemanticVulnAgent, run_semantic_agents
from crucible.agents.severity import SeverityAgent

__all__ = ["SemanticVulnAgent", "run_semantic_agents", "SeverityAgent"]
