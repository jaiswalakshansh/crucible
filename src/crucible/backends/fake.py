"""A scripted, deterministic backend for tests.

This exists so gate *orchestration* (prompt construction, JSON parsing, verdict
mapping, fail-open on malformed output) can be verified without a network call or
a real model. It does not simulate model quality and must never be used to make
any claim about accuracy — only about control flow.

Two modes:
- ``responses``: a queue of canned strings returned in order.
- ``matcher``: a callable mapping the last user message to a response string.
"""

from __future__ import annotations

import json
from typing import Callable

from crucible.backends.base import LLMBackend, LLMMessage, LLMResponse


class FakeBackend(LLMBackend):
    name = "fake"

    def __init__(
        self,
        responses: list[str] | None = None,
        *,
        matcher: Callable[[str], str] | None = None,
        model_name: str = "fake-model",
    ) -> None:
        self._responses = list(responses or [])
        self._matcher = matcher
        self._model_name = model_name
        self.calls: list[list[LLMMessage]] = []

    def complete(
        self,
        messages: list[LLMMessage],
        *,
        json_mode: bool = False,
        temperature: float = 0.0,
        max_tokens: int | None = None,
    ) -> LLMResponse:
        self.calls.append(messages)
        if self._matcher is not None:
            last_user = next(
                (m.content for m in reversed(messages) if m.role == "user"), ""
            )
            text = self._matcher(last_user)
        elif self._responses:
            text = self._responses.pop(0)
        else:
            raise RuntimeError("FakeBackend exhausted: no scripted response left")

        parsed = None
        if json_mode:
            # Mirror a real backend: try to parse, leave None if the script
            # returned malformed JSON (so fail-open paths can be tested).
            try:
                parsed = json.loads(text)
            except json.JSONDecodeError:
                parsed = None
        return LLMResponse(text=text, model=self._model_name, parsed=parsed)
