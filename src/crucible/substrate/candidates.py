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
from crucible.substrate.interproc import (
    analyze_project,
    analyze_source_interprocedural,
)
from crucible.substrate.languages import detect_language
from crucible.substrate.taint import analyze_source

_SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build"}


def analyze_file(path: str, *, interprocedural: bool = True) -> list[Finding]:
    lang = detect_language(path)
    if lang is None:
        return []
    try:
        with open(path, encoding="utf-8") as fh:
            source = fh.read()
    except (OSError, UnicodeDecodeError):
        return []
    if interprocedural:
        return analyze_source_interprocedural(source, lang.name, path=path)
    return analyze_source(source, lang.name, path=path)


def taint_candidates(target: str, *, interprocedural: bool = True) -> list[Finding]:
    """Candidate source usable directly as a ``Pipeline`` candidate_source.

    Accepts a single file or a directory. Returns [] for unsupported files.
    """
    if os.path.isfile(target):
        return analyze_file(target, interprocedural=interprocedural)

    # Directory: Python files are analyzed together (cross-file resolution); other
    # supported languages are analyzed per file.
    py_sources: dict[str, str] = {}
    other_files: list[str] = []
    for dirpath, dirnames, filenames in os.walk(target):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        for name in filenames:
            path = os.path.join(dirpath, name)
            lang = detect_language(path)
            if lang is None:
                continue
            if lang.name == "python":
                try:
                    with open(path, encoding="utf-8") as fh:
                        py_sources[path] = fh.read()
                except (OSError, UnicodeDecodeError):
                    continue
            else:
                other_files.append(path)

    out: list[Finding] = []
    if py_sources:
        out.extend(analyze_project(py_sources, language="python"))
    for path in other_files:
        out.extend(analyze_file(path, interprocedural=interprocedural))
    return out
