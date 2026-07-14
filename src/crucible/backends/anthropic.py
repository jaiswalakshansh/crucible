"""Anthropic backend.

Implemented against the Messages API using only the standard library (urllib), so
the package has no runtime dependencies. Reads the key from ``ANTHROPIC_API_KEY``.

Verification status: NOT exercised by the test suite and NOT run in CI. It makes
a live network call, so it is only reachable when a key is configured. Treat its
behavior as unverified in this repo until an integration test with a real key is
added.
"""

from __future__ import annotations

import json
import os
import urllib.request
from typing import Any

from crucible.backends.base import LLMBackend, LLMMessage, LLMResponse

_API_URL = "https://api.anthropic.com/v1/messages"
_API_VERSION = "2023-06-01"


class AnthropicBackend(LLMBackend):
    def __init__(
        self,
        model: str = "claude-sonnet-5",
        *,
        api_key: str | None = None,
        max_tokens: int = 4096,
    ) -> None:
        self._model = model
        self._api_key = api_key or os.environ.get("ANTHROPIC_API_KEY")
        self._default_max_tokens = max_tokens

    @property
    def name(self) -> str:  # type: ignore[override]
        return f"anthropic:{self._model}"

    def complete(
        self,
        messages: list[LLMMessage],
        *,
        json_mode: bool = False,
        temperature: float = 0.0,
        max_tokens: int | None = None,
    ) -> LLMResponse:
        if not self._api_key:
            raise RuntimeError(
                "ANTHROPIC_API_KEY is not set; the Anthropic backend cannot run."
            )
        system = "\n\n".join(m.content for m in messages if m.role == "system")
        turns = [
            {"role": m.role, "content": m.content}
            for m in messages
            if m.role in ("user", "assistant")
        ]
        if json_mode:
            system += (
                "\n\nRespond with a single valid JSON object and nothing else."
            )
        payload: dict[str, Any] = {
            "model": self._model,
            "max_tokens": max_tokens or self._default_max_tokens,
            "temperature": temperature,
            "messages": turns,
        }
        if system.strip():
            payload["system"] = system

        req = urllib.request.Request(
            _API_URL,
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "content-type": "application/json",
                "x-api-key": self._api_key,
                "anthropic-version": _API_VERSION,
            },
            method="POST",
        )
        with urllib.request.urlopen(req) as resp:  # noqa: S310 (fixed host)
            body = json.loads(resp.read().decode("utf-8"))

        text = "".join(
            block.get("text", "")
            for block in body.get("content", [])
            if block.get("type") == "text"
        )
        parsed = None
        if json_mode:
            try:
                parsed = json.loads(text)
            except json.JSONDecodeError:
                parsed = None
        return LLMResponse(
            text=text,
            model=self._model,
            parsed=parsed,
            usage=body.get("usage", {}),
        )
