"""The backend contract every LLM provider implements.

Deliberately tiny: one ``complete`` call in, one structured response out. Keeping
the surface minimal is what lets the harness treat Claude, GPT, and local models
as interchangeable and mix them within a single scan.
"""

from __future__ import annotations

import abc
from dataclasses import dataclass, field
from typing import Any


@dataclass
class LLMMessage:
    role: str  # "system" | "user" | "assistant"
    content: str


@dataclass
class LLMResponse:
    text: str
    model: str
    # Populated when the caller requested JSON and the backend parsed it.
    parsed: dict[str, Any] | None = None
    usage: dict[str, int] = field(default_factory=dict)


class LLMBackend(abc.ABC):
    """A single model behind one uniform interface.

    Implementations live in sibling modules (e.g. ``anthropic.py``, ``openai.py``)
    and register themselves via ``registry.register_backend``. This module has no
    provider dependencies so importing it is always cheap and side-effect free.
    """

    #: Short stable id used in config and in ``Finding.source`` provenance.
    name: str = "abstract"

    @abc.abstractmethod
    def complete(
        self,
        messages: list[LLMMessage],
        *,
        json_mode: bool = False,
        temperature: float = 0.0,
        max_tokens: int | None = None,
    ) -> LLMResponse:
        """Run a single completion. ``json_mode`` asks the backend to return
        strict JSON and populate ``LLMResponse.parsed``."""
        raise NotImplementedError
