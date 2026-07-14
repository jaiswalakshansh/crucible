"""Backend registry — name -> factory.

Providers register a zero-arg (or config-driven) factory under a short name so
config files and the harness can request models by string ("claude-strong",
"gpt-cheap") without importing provider SDKs until they are actually used.
"""

from __future__ import annotations

from typing import Callable

from crucible.backends.base import LLMBackend

_REGISTRY: dict[str, Callable[[], LLMBackend]] = {}


def register_backend(name: str, factory: Callable[[], LLMBackend]) -> None:
    _REGISTRY[name] = factory


def get_backend(name: str) -> LLMBackend:
    if name not in _REGISTRY:
        raise KeyError(
            f"No backend registered under {name!r}. "
            f"Available: {sorted(_REGISTRY) or '(none yet)'}"
        )
    return _REGISTRY[name]()


def available_backends() -> list[str]:
    return sorted(_REGISTRY)
