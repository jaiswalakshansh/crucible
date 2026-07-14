"""Optional convenience registrations.

Importing this module registers the built-in backends by name. It is kept
separate from ``backends/__init__.py`` so that importing the package does not
force provider modules to load. Callers who want the registry populated do
``import crucible.backends.defaults``.

Note: registering a backend does not construct it. The Anthropic factory only
builds a client when requested, and that client only makes a network call when
``complete`` is invoked with a key present.
"""

from __future__ import annotations

from crucible.backends.anthropic import AnthropicBackend
from crucible.backends.fake import FakeBackend
from crucible.backends.registry import register_backend

register_backend("anthropic", lambda: AnthropicBackend())
register_backend("fake", lambda: FakeBackend())
