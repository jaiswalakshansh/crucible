"""Gated live-model test for a semantic agent.

Skipped unless ANTHROPIC_API_KEY is set (so it does not run in CI or in the
environment where this was written). It checks the mechanics against a real model
on an obvious IDOR — NOT that the model is always right. Detection quality is a
benchmark question, not asserted here.

    ANTHROPIC_API_KEY=... pytest tests/integration/test_live_semantic.py -q
"""

import os

import pytest

from crucible.agents import SemanticVulnAgent
from crucible.backends.anthropic import AnthropicBackend
from crucible.skills import SkillRegistry

pytestmark = pytest.mark.skipif(
    not os.environ.get("ANTHROPIC_API_KEY"),
    reason="no ANTHROPIC_API_KEY; live semantic-agent test skipped",
)

SKILLS_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "skills")


def test_semantic_agent_runs_against_real_model():
    skill = SkillRegistry.from_dir(SKILLS_DIR).get("broken-access-control")
    code = (
        "def get_order(request, order_id):\n"
        "    # no check that the order belongs to the current user\n"
        "    return Order.objects.get(id=order_id)\n"
    )
    agent = SemanticVulnAgent(skill, AnthropicBackend())
    findings = agent.analyze(code, "orders.py")
    # Assert the mechanics produced well-formed findings (or none) without error.
    for f in findings:
        assert f.rule_id == "crucible.broken-access-control"
        assert f.confirmation.value == "suspected"
        assert f.location.start_line >= 1
