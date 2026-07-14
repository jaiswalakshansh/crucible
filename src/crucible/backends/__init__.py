"""Pluggable LLM backends.

Adversarial validation is the highest-ROI false-positive reducer we have, and it
*requires* a second, different model to disprove the first. So a multi-model,
one-schema interface is not a nicety here — it is load-bearing. Every backend
implements the same ``LLMBackend`` contract; the harness picks a strong model for
validation and a cheap one for recon.
"""

from crucible.backends.base import LLMBackend, LLMMessage, LLMResponse
from crucible.backends.registry import get_backend, register_backend

__all__ = [
    "LLMBackend",
    "LLMMessage",
    "LLMResponse",
    "get_backend",
    "register_backend",
]
