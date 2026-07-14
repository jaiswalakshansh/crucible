"""Turn the taint analysis into a directory-walking candidate source.

This is the deterministic front of the pipeline: walk a target, parse each
supported file, run taint analysis, and yield findings whose evidence already
contains a real source→sink path. Those candidates then feed the validation
ladder (the taint path grounds the LLM gates and gives the deterministic
pre-filter genuine reachability data instead of a guess).
"""

from __future__ import annotations

import os

from crucible.schema.finding import Finding
from crucible.substrate.languages import detect_language
from crucible.substrate.taint import analyze_source

_SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build"}


def analyze_file(path: str) -> list[Finding]:
    lang = detect_language(path)
    if lang is None:
        return []
    try:
        with open(path, encoding="utf-8") as fh:
            source = fh.read()
    except (OSError, UnicodeDecodeError):
        return []
    findings = analyze_source(source, lang.name, path=path)
    return findings


def taint_candidates(target: str) -> list[Finding]:
    """Candidate source usable directly as a ``Pipeline`` candidate_source.

    Accepts a single file or a directory. Returns [] for unsupported files.
    """
    if os.path.isfile(target):
        return analyze_file(target)
    out: list[Finding] = []
    for dirpath, dirnames, filenames in os.walk(target):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        for name in filenames:
            out.extend(analyze_file(os.path.join(dirpath, name)))
    return out
