"""Taint rule packs: sources, sinks, sanitizers per language.

Pattern-based, matched against the textual callee of a call (e.g.
``request.args.get``) or the target of an assignment (e.g. ``el.innerHTML``).
They are the direct cause of both false negatives (a real source/sink not listed)
and false positives (an over-broad pattern), and are meant to be extended.

Source kinds:
- ``sources``      — untrusted external input (kind "user").
- ``llm_sources``  — values returned by an LLM/model call (kind "llm"); used to
  detect insecure handling of LLM output (LLM output reaching a dangerous sink).

Sink kinds:
- ``sinks``        — dangerous *call* sinks (checked against arg 0).
- ``assign_sinks`` — dangerous *assignment targets* (e.g. ``.innerHTML =``), for
  cases where the danger is writing tainted data to a property, not a call.

Deliberately NOT modeled: prompt injection (user input reaching the model prompt).
Every LLM app routes user input to the model, so flagging that as taint would be
almost all false positives; whether guardrails exist is not visible to static
analysis. We cover insecure *output* handling instead, which is a real flow with a
dangerous sink.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Matcher:
    substrings: frozenset[str] = field(default_factory=frozenset)
    exact: frozenset[str] = field(default_factory=frozenset)

    def matches(self, text: str) -> bool:
        if text in self.exact:
            return True
        return any(s in text for s in self.substrings)


@dataclass(frozen=True)
class TaintRules:
    language: str
    sources: Matcher
    sinks: Matcher
    sanitizers: Matcher
    llm_sources: Matcher = Matcher()
    assign_sinks: Matcher = Matcher()
    # Ordered (needle, rule_id, cwe); first match wins. Order matters: put specific
    # needles before generic ones (e.g. ".execute" before "exec").
    sink_labels: tuple[tuple[str, str, str], ...] = ()
    fallback_label: tuple[str, str] = ("crucible.tainted-sink", "CWE-20")

    def label_for(self, text: str) -> tuple[str, str]:
        for needle, rule_id, cwe in self.sink_labels:
            if needle in text:
                return rule_id, cwe
        return self.fallback_label


# --- Python ---------------------------------------------------------------------

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
_PY_LLM_SOURCES = Matcher(
    substrings=frozenset(
        {
            ".messages.create",
            ".completions.create",
            ".chat.completions.create",
            ".generate_content",
            "llm.invoke",
            "chain.invoke",
            ".predict_messages",
        }
    ),
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
            # SSRF
            "requests.get",
            "requests.post",
            "requests.put",
            "requests.request",
            "urllib.request.urlopen",
            "urlopen",
            "httpx.get",
            "httpx.post",
            # path traversal
            "os.open",
            "send_file",
            "send_from_directory",
            # SSTI
            "render_template_string",
            ".from_string",
        }
    ),
    exact=frozenset({"eval", "exec", "open", "Template"}),
)
_PY_SANITIZERS = Matcher(
    substrings=frozenset(
        {"escape", "quote", "sanitize", "shlex.quote", "secure_filename", "basename"}
    ),
    exact=frozenset({"int", "float", "bool"}),
)
_PY_SINK_LABELS = (
    (".executemany", "crucible.sql-injection", "CWE-89"),
    (".executescript", "crucible.sql-injection", "CWE-89"),
    (".execute", "crucible.sql-injection", "CWE-89"),
    (".raw", "crucible.sql-injection", "CWE-89"),
    ("os.system", "crucible.command-injection", "CWE-78"),
    ("subprocess", "crucible.command-injection", "CWE-78"),
    ("render_template_string", "crucible.ssti", "CWE-1336"),
    (".from_string", "crucible.ssti", "CWE-1336"),
    ("Template", "crucible.ssti", "CWE-1336"),
    ("requests.", "crucible.ssrf", "CWE-918"),
    ("httpx.", "crucible.ssrf", "CWE-918"),
    ("urlopen", "crucible.ssrf", "CWE-918"),
    ("send_file", "crucible.path-traversal", "CWE-22"),
    ("send_from_directory", "crucible.path-traversal", "CWE-22"),
    ("os.open", "crucible.path-traversal", "CWE-22"),
    ("open", "crucible.path-traversal", "CWE-22"),
    ("eval", "crucible.code-injection", "CWE-95"),
    ("exec", "crucible.code-injection", "CWE-95"),
)


# --- JavaScript / TypeScript ----------------------------------------------------

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
            # DOM sources
            "location.search",
            "location.hash",
            "location.href",
            "document.URL",
            "document.cookie",
            "document.referrer",
            "window.name",
            "document.location",
        }
    ),
)
_JS_LLM_SOURCES = Matcher(
    substrings=frozenset(
        {".messages.create", ".completions.create", ".generateContent", "llm.invoke"}
    ),
)
_JS_SINKS = Matcher(
    substrings=frozenset(
        {".query", ".execute", "child_process.exec", ".exec", "document.write", ".insertAdjacentHTML"}
    ),
    exact=frozenset({"eval"}),
)
_JS_ASSIGN_SINKS = Matcher(
    substrings=frozenset({".innerHTML", ".outerHTML", "dangerouslySetInnerHTML"}),
)
_JS_SANITIZERS = Matcher(
    substrings=frozenset({"escape", "sanitize", "encodeURIComponent", "DOMPurify"}),
    exact=frozenset({"parseInt", "parseFloat", "Number"}),
)
_JS_SINK_LABELS = (
    (".query", "crucible.sql-injection", "CWE-89"),
    (".execute", "crucible.sql-injection", "CWE-89"),
    ("document.write", "crucible.dom-xss", "CWE-79"),
    (".insertAdjacentHTML", "crucible.dom-xss", "CWE-79"),
    (".innerHTML", "crucible.dom-xss", "CWE-79"),
    (".outerHTML", "crucible.dom-xss", "CWE-79"),
    ("dangerouslySetInnerHTML", "crucible.dom-xss", "CWE-79"),
    ("child_process", "crucible.command-injection", "CWE-78"),
    (".exec", "crucible.command-injection", "CWE-78"),
    ("eval", "crucible.code-injection", "CWE-95"),
)


RULES: dict[str, TaintRules] = {
    "python": TaintRules(
        language="python",
        sources=_PY_SOURCES,
        sinks=_PY_SINKS,
        sanitizers=_PY_SANITIZERS,
        llm_sources=_PY_LLM_SOURCES,
        sink_labels=_PY_SINK_LABELS,
    ),
    "javascript": TaintRules(
        language="javascript",
        sources=_JS_SOURCES,
        sinks=_JS_SINKS,
        sanitizers=_JS_SANITIZERS,
        llm_sources=_JS_LLM_SOURCES,
        assign_sinks=_JS_ASSIGN_SINKS,
        sink_labels=_JS_SINK_LABELS,
    ),
}
RULES["typescript"] = TaintRules(
    language="typescript",
    sources=_JS_SOURCES,
    sinks=_JS_SINKS,
    sanitizers=_JS_SANITIZERS,
    llm_sources=_JS_LLM_SOURCES,
    assign_sinks=_JS_ASSIGN_SINKS,
    sink_labels=_JS_SINK_LABELS,
)


def rules_for(language: str) -> TaintRules | None:
    return RULES.get(language)
