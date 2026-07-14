"""Gated live-backend integration test.

This is the one test that exercises a real model. It is skipped unless
``ANTHROPIC_API_KEY`` is set, so it does not run in CI and did not run in the
environment where this code was written. When you have a key:

    ANTHROPIC_API_KEY=... pytest tests/integration -q

It runs the adversarial gate against a real model on one obvious true positive
and one obvious safe case, and checks only that the gate produces a well-formed,
non-fail-open verdict — NOT that the model is always right. Model accuracy is not
asserted here; that requires a benchmark, which is separate work.
"""

import os

import pytest

from crucible.backends.anthropic import AnthropicBackend
from crucible.substrate.taint import analyze_source
from crucible.validators.gates import AdversarialGate

pytestmark = pytest.mark.skipif(
    not os.environ.get("ANTHROPIC_API_KEY"),
    reason="no ANTHROPIC_API_KEY; live backend test skipped",
)


def test_adversarial_gate_returns_wellformed_verdict_on_real_model():
    src = 'def h(request):\n    db.execute("SELECT * WHERE id = " + request.args.get("id"))\n'
    finding = analyze_source(src, "python")[0]
    finding.evidence["code"] = src
    gate = AdversarialGate(AnthropicBackend())
    verdict = gate.evaluate(finding)
    # We assert the mechanics worked (a real verdict came back), not the ruling.
    assert verdict.failed_open is False
    assert isinstance(verdict.passed, bool)
    assert verdict.detail
