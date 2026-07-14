"""Language registry — the language-agnostic contract in one place.

A language is *supported* when it declares its file extensions here. Deeper
capabilities (taint depth, PoC sandbox) are tracked per-language so the engine
can degrade gracefully — a new language starts at structural + LLM-reasoning
coverage and never hard-fails as "unsupported".
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Language:
    name: str
    extensions: tuple[str, ...]
    # Capability flags — honestly track what actually works for this language.
    tree_sitter: bool = False
    opengrep: bool = False
    deep_taint: bool = False
    poc_sandbox: bool = False


# Capability flags reflect what is actually implemented and tested, not aspiration.
# deep_taint is True only where a tree-sitter taint adapter exists and is tested
# (Python, JS, TS). Go and Java parse via tree-sitter but have no taint adapter yet.
LANGUAGES: dict[str, Language] = {
    "python": Language("python", (".py",), tree_sitter=True, opengrep=True,
                       deep_taint=True),
    "javascript": Language("javascript", (".js", ".jsx", ".mjs", ".cjs"),
                           tree_sitter=True, opengrep=True, deep_taint=True),
    "typescript": Language("typescript", (".ts", ".tsx"),
                           tree_sitter=True, opengrep=True, deep_taint=True),
    "go": Language("go", (".go",), tree_sitter=True, opengrep=True),
    "java": Language("java", (".java",), tree_sitter=True, opengrep=True),
}

_EXT_INDEX: dict[str, Language] = {
    ext: lang for lang in LANGUAGES.values() for ext in lang.extensions
}


def detect_language(path: str) -> Language | None:
    """Best-effort language detection by extension. Returns None (not an error)
    for unknown files — callers decide whether to skip or apply generic passes."""
    for ext, lang in _EXT_INDEX.items():
        if path.endswith(ext):
            return lang
    return None
