"""Taint rule packs: sources, sinks, sanitizers per language.

These are deliberately a small, pattern-based starter set matched against the
textual callee of a call (e.g. ``request.args.get``). They are the direct cause of
both false negatives (a real source/sink whose pattern is not listed) and false
positives (an over-broad pattern). They are meant to be extended. Matching is:
- ``substrings``: the callee text contains the pattern anywhere.
- ``exact``: the callee text equals the pattern.

Each rule pack also names the CWE and rule id used for findings it produces.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Matcher:
    substrings: frozenset[str] = field(default_factory=frozenset)
    exact: frozenset[str] = field(default_factory=frozenset)

    def matches(self, callee: str) -> bool:
        if callee in self.exact:
            return True
        return any(s in callee for s in self.substrings)


@dataclass(frozen=True)
class TaintRules:
    language: str
    sources: Matcher
    sinks: Matcher
    sanitizers: Matcher
    # Sink-callee substring -> (rule_id, cwe). First match wins; fallback used
    # when nothing matches.
    sink_labels: tuple[tuple[str, str, str], ...] = ()
    fallback_label: tuple[str, str] = ("crucible.tainted-sink", "CWE-20")

    def label_for(self, callee: str) -> tuple[str, str]:
        for needle, rule_id, cwe in self.sink_labels:
            if needle in callee:
                return rule_id, cwe
        return self.fallback_label


_PY_SOURCES = Matcher(
    substrings=frozenset(
        {
            "request.args",
            "request.form",
            "request.values",
            "request.cookies",
            "request.headers",
            "request.get_json",
            "request.json",
            "request.data",
            "request.GET",
            "request.POST",
            "os.environ",
            "sys.argv",
        }
    ),
    exact=frozenset({"input"}),
)
_PY_SINKS = Matcher(
    substrings=frozenset(
        {
            ".execute",
            ".executemany",
            ".executescript",
            ".raw",
            "os.system",
            "subprocess.Popen",
            "subprocess.call",
            "subprocess.run",
            "subprocess.check_output",
        }
    ),
    exact=frozenset({"eval", "exec"}),
)
_PY_SANITIZERS = Matcher(
    substrings=frozenset({"escape", "quote", "sanitize", "shlex.quote"}),
    exact=frozenset({"int", "float", "bool"}),
)

_JS_SOURCES = Matcher(
    substrings=frozenset(
        {
            "req.query",
            "req.params",
            "req.body",
            "req.headers",
            "req.cookies",
            "request.query",
            "request.body",
            "process.argv",
            "process.env",
            "location.search",
            "location.hash",
            "window.name",
            "document.location",
        }
    ),
)
_JS_SINKS = Matcher(
    substrings=frozenset({".query", ".execute", "child_process.exec", ".exec"}),
    exact=frozenset({"eval"}),
)
_JS_SANITIZERS = Matcher(
    substrings=frozenset({"escape", "sanitize", "encodeURIComponent"}),
    exact=frozenset({"parseInt", "parseFloat", "Number"}),
)

_SQLI_SINKS = (".execute", ".executemany", ".executescript", ".raw", ".query")
_CMDI_SINKS = ("os.system", "subprocess", "child_process", ".exec")

RULES: dict[str, TaintRules] = {
    "python": TaintRules(
        language="python",
        sources=_PY_SOURCES,
        sinks=_PY_SINKS,
        sanitizers=_PY_SANITIZERS,
        sink_labels=(
            (".execute", "crucible.sql-injection", "CWE-89"),
            (".raw", "crucible.sql-injection", "CWE-89"),
            ("os.system", "crucible.command-injection", "CWE-78"),
            ("subprocess", "crucible.command-injection", "CWE-78"),
            ("eval", "crucible.code-injection", "CWE-95"),
            ("exec", "crucible.code-injection", "CWE-95"),
        ),
    ),
    "javascript": TaintRules(
        language="javascript",
        sources=_JS_SOURCES,
        sinks=_JS_SINKS,
        sanitizers=_JS_SANITIZERS,
        sink_labels=(
            (".query", "crucible.sql-injection", "CWE-89"),
            (".execute", "crucible.sql-injection", "CWE-89"),
            ("exec", "crucible.command-injection", "CWE-78"),
            ("eval", "crucible.code-injection", "CWE-95"),
        ),
    ),
}
RULES["typescript"] = TaintRules(
    language="typescript",
    sources=_JS_SOURCES,
    sinks=_JS_SINKS,
    sanitizers=_JS_SANITIZERS,
    sink_labels=RULES["javascript"].sink_labels,
)


def rules_for(language: str) -> TaintRules | None:
    return RULES.get(language)
