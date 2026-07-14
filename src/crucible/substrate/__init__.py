"""L0 — the universal, language-agnostic code substrate.

One code model for every language. Nothing above this layer knows what language
it is looking at:

- ``parser``   — tree-sitter parsing to a uniform AST (per-language grammar in,
  language-neutral nodes out).
- ``opengrep`` — the deterministic detector floor: Opengrep (open cross-function
  taint, 12 languages, SARIF native) run as a subprocess, findings parsed into
  the Crucible ``Finding`` contract.

Planned siblings: ``index`` (SCIP / stack-graphs for cross-file & cross-repo name
resolution) and ``cpg`` (a Code Property Graph as the source->sink IR).

The contract for adding a language lives in ``LANGUAGES``: provide a grammar,
an indexer, and source/sink/sanitizer specs — no changes above L0.
"""

from crucible.substrate.opengrep import OpengrepAdapter
from crucible.substrate.languages import LANGUAGES, Language, detect_language
from crucible.substrate.taint import analyze_source
from crucible.substrate.candidates import analyze_file, taint_candidates

__all__ = [
    "OpengrepAdapter",
    "LANGUAGES",
    "Language",
    "detect_language",
    "analyze_source",
    "analyze_file",
    "taint_candidates",
]
