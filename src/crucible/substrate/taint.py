"""Intra-procedural taint analysis over a tree-sitter tree.

Scope and honest limitations:

- **Intra-procedural.** Taint is tracked within a single function body (and the
  module top level). Flows that cross function boundaries are NOT followed, so
  cross-function vulnerabilities are false negatives. Inter-procedural analysis via
  a call graph is future work.
- **Document-order, not full control flow.** Statements are processed in source
  order; branches and loops are not precisely modeled. This can both miss flows
  and, more rarely, over-report.
- **Pattern-based sources/sinks.** See ``taint_rules``. Anything not in the rule
  packs is missed.
- **Parameters untainted by default.** Function parameters are not treated as
  tainted unless ``taint_params=True``, trading recall for precision.

What it does correctly (and is tested): within a scope, it propagates taint from a
source call through assignments and string building into a sink argument, respects
sanitizers, and emits a finding with an explicit source→sink path. This produces
real reachability evidence to ground the validation gates, rather than a guess.
"""

from __future__ import annotations

from typing import Any

from crucible.schema.finding import Finding, Location, Severity
from crucible.substrate.adapters import LanguageAdapter, adapter_for
from crucible.substrate.taint_rules import TaintRules, rules_for
from crucible.substrate.treesitter import get_tree, node_line, node_text


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
        # The module top level is a scope; each function body is a nested scope.
        self._analyze_scope(root, params=[])
        for func in self._iter_functions(root):
            body = self.a.function_body(func)
            if body is not None:
                self._analyze_scope(body, params=self.a.param_names(func))

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

    def _analyze_scope(self, scope: Any, params: list[str]) -> None:
        tainted: dict[str, int] = {}
        if self.taint_params:
            for p in params:
                tainted[p] = node_line(scope)
        for node in self._walk_scope(scope):
            assignment = self.a.as_assignment(node)
            if assignment is not None:
                name, value = assignment
                src = self._expr_taint(value, tainted)
                if name is not None:
                    if src is not None:
                        tainted[name] = src
                    else:
                        tainted.pop(name, None)
                continue
            call = self.a.as_call(node)
            if call is not None:
                callee, args = call
                if self.rules.sinks.matches(callee):
                    self._check_sink(node, callee, args, tainted)

    def _walk_scope(self, scope: Any):
        """Pre-order nodes within ``scope``, not descending into nested functions
        (those are analyzed as their own scopes)."""
        for child in scope.children:
            if self.a.is_function(child):
                continue
            yield child
            yield from self._walk_scope(child)

    def _check_sink(
        self, call_node: Any, callee: str, args: list[Any], tainted: dict[str, int]
    ) -> None:
        # Only the first positional argument is the dangerous position for the
        # sinks in our rule packs (the SQL query string / command / code string).
        # This is what makes parameterized queries — e.g.
        # ``execute("... = ?", (uid,))`` — correctly safe even when a later
        # argument is tainted. Documented limitation: sinks whose dangerous input
        # is not the first argument are not covered.
        if not args:
            return
        src_line = self._expr_taint(args[0], tainted)
        if src_line is not None:
            self._emit(call_node, callee, src_line)

    def _expr_taint(self, node: Any, tainted: dict[str, int]) -> int | None:
        """Return the source line if ``node`` evaluates to tainted data, else None."""
        call = self.a.as_call(node)
        if call is not None:
            callee, _ = call
            if self.rules.sanitizers.matches(callee):
                return None
            if self.rules.sources.matches(callee):
                return node_line(node)
            # else: fall through to recurse into receiver/args
        # Property/index access sources that are not calls, e.g. ``req.query.id``
        # or ``request.args["id"]``.
        if node.type in self.a.access_types:
            if self.rules.sources.matches(node_text(node)):
                return node_line(node)
            # else fall through: the base object may itself be a tainted variable.
        name = self.a.identifier_name(node)
        if name is not None:
            return tainted.get(name)
        if self.a.is_string_literal(node):
            return None
        best: int | None = None
        for child in node.children:
            src = self._expr_taint(child, tainted)
            if src is not None and (best is None or src < best):
                best = src
        return best

    def _emit(self, call_node: Any, callee: str, source_line: int) -> None:
        sink_line = node_line(call_node)
        key = (source_line, sink_line)
        if key in self._seen:
            return
        self._seen.add(key)
        rule_id, cwe = self.rules.label_for(callee)
        finding = Finding(
            rule_id=rule_id,
            message=(
                f"tainted data reaches {callee} without sanitization "
                f"(source at line {source_line})"
            ),
            severity=Severity.HIGH,
            location=Location(path=self.path, start_line=sink_line),
            source="crucible-taint",
            cwe=cwe,
        )
        finding.evidence["taint"] = {
            "reachable": True,
            "path": [
                {"role": "source", "line": source_line},
                {"role": "sink", "line": sink_line, "callee": callee},
            ],
        }
        finding.evidence["code"] = node_text(call_node)
        self.findings.append(finding)
