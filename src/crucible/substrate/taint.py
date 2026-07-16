"""Intra-procedural taint analysis over a tree-sitter tree.

Scope and honest limitations:

- **Intra-procedural.** Taint is tracked within a single function body (and the
  module top level). Flows crossing function boundaries are NOT followed and are
  false negatives. Inter-procedural analysis is future work (ROADMAP R1).
- **Document-order, not full control flow.** Statements are processed in source
  order; branches and loops are not precisely modeled.
- **Pattern-based sources/sinks.** See ``taint_rules``; anything not listed is missed.
- **Parameters untainted by default** (``taint_params``), trading recall for precision.

What it does and is tested: within a scope it propagates taint from a source
(user input, or LLM output) through assignments and string building into a sink —
either a dangerous call argument or a dangerous assignment target (e.g.
``el.innerHTML =``) — while respecting sanitizers, and emits a finding with an
explicit source→sink path. When the source is LLM output, the finding is labeled
as insecure-LLM-output-handling rather than by the sink alone.
"""

from __future__ import annotations

from typing import Any, NamedTuple

from crucible.schema.finding import Finding, Location, Severity
from crucible.substrate.adapters import LanguageAdapter, adapter_for
from crucible.substrate.taint_rules import TaintRules, rules_for
from crucible.substrate.treesitter import get_tree, node_line, node_text


class TaintMark(NamedTuple):
    line: int
    kind: str  # "user" (untrusted input) or "llm" (model output)
    origin: str | None = None  # source parameter name, when taint began at a param


# Sink classes for which exploitability can be proven by calling the function with
# a crafted argument (see crucible.exploit). Kept here so taint can flag which
# findings are candidates for proving.
EXECUTION_SINK_RULES = frozenset(
    {"crucible.code-injection", "crucible.command-injection"}
)


def analyze_source(
    source: str,
    language: str,
    *,
    path: str = "<memory>",
    taint_params: bool = False,
) -> list[Finding]:
    """Analyze ``source`` and return taint findings. Returns [] if the language
    has no taint adapter/rules (parsing-only languages degrade to no findings)."""
    adapter = adapter_for(language)
    rules = rules_for(language)
    if adapter is None or rules is None:
        return []
    tree = get_tree(source, language)
    analyzer = _Analyzer(adapter, rules, path, taint_params)
    analyzer.run(tree.root_node)
    return analyzer.findings


class _Analyzer:
    def __init__(
        self,
        adapter: LanguageAdapter,
        rules: TaintRules,
        path: str,
        taint_params: bool,
    ) -> None:
        self.a = adapter
        self.rules = rules
        self.path = path
        self.taint_params = taint_params
        self.findings: list[Finding] = []
        self._seen: set[tuple[int, int]] = set()

    def run(self, root: Any) -> None:
        self._analyze_scope(root, params=[], func_name=None)
        for func in self._iter_functions(root):
            body = self.a.function_body(func)
            if body is not None:
                self._analyze_scope(
                    body,
                    params=self.a.param_names(func),
                    func_name=self.a.function_name(func),
                )

    def _iter_functions(self, root: Any) -> list[Any]:
        found: list[Any] = []
        stack = [root]
        while stack:
            node = stack.pop()
            for child in node.children:
                if self.a.is_function(child):
                    found.append(child)
                stack.append(child)
        return found

    def _analyze_scope(
        self, scope: Any, params: list[str], func_name: str | None
    ) -> None:
        tainted: dict[str, TaintMark] = {}
        if self.taint_params:
            for p in params:
                tainted[p] = TaintMark(node_line(scope), "user", origin=p)
        for node in self._walk_scope(scope):
            assignment = self.a.as_assignment(node)
            if assignment is not None:
                self._handle_assignment(node, assignment, tainted, func_name)
                continue
            call = self.a.as_call(node)
            if call is not None:
                callee, args = call
                if self.rules.sinks.matches(callee):
                    self._check_call_sink(node, callee, args, tainted, func_name)

    def _handle_assignment(
        self,
        node: Any,
        assignment: tuple[Any, Any],
        tainted: dict[str, TaintMark],
        func_name: str | None,
    ) -> None:
        target, value = assignment
        mark = self._expr_taint(value, tainted)
        target_text = node_text(target)
        # Assignment-target sink, e.g. ``el.innerHTML = tainted``.
        if mark is not None and self.rules.assign_sinks.matches(target_text):
            self._emit(node, target_text, mark, func_name)
        # Variable binding (only for plain identifiers).
        name = self.a.identifier_name(target)
        if name is not None:
            if mark is not None:
                tainted[name] = mark
            else:
                tainted.pop(name, None)

    def _walk_scope(self, scope: Any):
        for child in scope.children:
            if self.a.is_function(child):
                continue
            yield child
            yield from self._walk_scope(child)

    def _check_call_sink(
        self,
        call_node: Any,
        callee: str,
        args: list[Any],
        tainted: dict[str, TaintMark],
        func_name: str | None,
    ) -> None:
        # Only the first positional argument is the dangerous position for the
        # sinks in our rule packs (query/command/code string/url/path). This is
        # what makes parameterized queries correctly safe.
        if not args:
            return
        mark = self._expr_taint(args[0], tainted)
        if mark is not None:
            self._emit(call_node, callee, mark, func_name)

    def _expr_taint(self, node: Any, tainted: dict[str, TaintMark]) -> TaintMark | None:
        call = self.a.as_call(node)
        if call is not None:
            callee, _ = call
            if self.rules.sanitizers.matches(callee):
                return None
            if self.rules.llm_sources.matches(callee):
                return TaintMark(node_line(node), "llm")
            if self.rules.sources.matches(callee):
                return TaintMark(node_line(node), "user")
            # else fall through to recurse into receiver/args
        if node.type in self.a.access_types:
            text = node_text(node)
            if self.rules.llm_sources.matches(text):
                return TaintMark(node_line(node), "llm")
            if self.rules.sources.matches(text):
                return TaintMark(node_line(node), "user")
            # else fall through: the base object may be a tainted variable.
        name = self.a.identifier_name(node)
        if name is not None:
            return tainted.get(name)
        if self.a.is_string_literal(node):
            return None
        best: TaintMark | None = None
        for child in node.children:
            mark = self._expr_taint(child, tainted)
            if mark is not None and (best is None or mark.line < best.line):
                best = mark
        return best

    def _emit(
        self, sink_node: Any, sink_text: str, mark: TaintMark, func_name: str | None
    ) -> None:
        sink_line = node_line(sink_node)
        key = (mark.line, sink_line)
        if key in self._seen:
            return
        self._seen.add(key)
        rule_id, cwe = self.rules.label_for(sink_text)
        if mark.kind == "llm":
            rule_id = "crucible.insecure-llm-output-handling"
            message = (
                f"LLM output reaches {sink_text} without validation "
                f"(model output at line {mark.line})"
            )
        else:
            message = (
                f"tainted data reaches {sink_text} without sanitization "
                f"(source at line {mark.line})"
            )
        finding = Finding(
            rule_id=rule_id,
            message=message,
            severity=Severity.HIGH,
            location=Location(path=self.path, start_line=sink_line),
            source="crucible-taint",
            cwe=cwe,
        )
        finding.evidence["taint"] = {
            "reachable": True,
            "source_kind": mark.kind,
            "path": [
                {"role": "source", "line": mark.line, "kind": mark.kind},
                {"role": "sink", "line": sink_line, "target": sink_text},
            ],
        }
        finding.evidence["code"] = node_text(sink_node)
        # If this is an execution sink reached from a function parameter, record
        # enough for the exploit prover to build a PoC that calls the function.
        if (
            rule_id in EXECUTION_SINK_RULES
            and mark.origin is not None
            and func_name is not None
        ):
            finding.evidence["exploit"] = {
                "function": func_name,
                "param": mark.origin,
                "sink_class": rule_id,
            }
        self.findings.append(finding)
