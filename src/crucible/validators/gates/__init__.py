"""Concrete validation gates.

- ``PrefilterGate``      — deterministic reachability annotation (no LLM).
- ``AdversarialGate``    — LLM gate that tries to disprove the finding.
- ``ReachabilityGate``   — LLM gate that assesses source->sink reachability.

Each gate's control flow (verdict mapping, fail-open on error/malformed output)
is unit-tested with a scripted backend in tests/test_gates.py. The accuracy of
the LLM gates' judgments is not measured in this repo.
"""

from crucible.validators.gates.prefilter import PrefilterGate
from crucible.validators.gates.adversarial import AdversarialGate
from crucible.validators.gates.reachability import ReachabilityGate
from crucible.validators.gates.poc import PoCGate

__all__ = ["PrefilterGate", "AdversarialGate", "ReachabilityGate", "PoCGate"]
