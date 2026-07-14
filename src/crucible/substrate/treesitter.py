"""tree-sitter parsing — the language-agnostic front end.

Parsers are obtained from ``tree-sitter-language-pack`` (precompiled grammars) and
cached per language. Parsing is deterministic and does not require any network or
model. If the language pack is unavailable for some reason, ``get_tree`` raises a
clear error rather than failing silently.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Any


@lru_cache(maxsize=None)
def _parser(language: str) -> Any:
    from tree_sitter_language_pack import get_parser

    return get_parser(language)


def get_tree(source: str, language: str) -> Any:
    """Parse ``source`` and return the tree-sitter tree."""
    return _parser(language).parse(source.encode("utf-8"))


def node_text(node: Any) -> str:
    return node.text.decode("utf-8", "replace")


def node_line(node: Any) -> int:
    """1-based start line."""
    return node.start_point[0] + 1
