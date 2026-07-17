"""Inter-procedural taint via function summaries (intra-file).

The intra-procedural analyzer misses the most common real shape: a handler reads
input and passes it to a helper that hits the sink. This module closes that gap
for functions defined in the same file.

Approach (standard summary-based dataflow):

1. Collect every named function in the file.
2. Compute a summary per function, to a fixpoint:
   - ``sink_params``: parameters that, if tainted, reach a sink (directly or via a
     call to another local function whose summary says so).
   - ``return_params``: parameters that, if tainted, taint the return value.
   - ``return_uncond``: the function returns tainted data from an internal source
     regardless of its parameters.
3. Main pass: analyze the module and each function body with *real* sources (not
   assumed-tainted parameters). At a call to a local function, consult its summary
   to (a) emit a cross-function finding when a tainted argument reaches a param in
   ``sink_params``, and (b) propagate taint through the return.

Honest limits:
- **Intra-file only.** Calls into other modules are not resolved (cross-file is
  future work); such calls fall back to the intra-procedural over-approximation.
- **Positional arguments only.** Keyword/spread arguments are not mapped to params.
- **Functions matched by base name** (last dotted segment); name collisions resolve
  to one definition. Document-order and control-flow limits of the intra analyzer
  still apply.

The result is a superset of the intra-procedural findings (it reproduces them and
adds cross-function ones), so it never loses a finding the intra analyzer had.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from crucible.schema.finding import Finding, Location, Severity
from crucible.substrate.adapters import LanguageAdapter, adapter_for
from crucible.substrate.taint import EXECUTION_SINK_RULES, TaintMark
from crucible.substrate.taint_rules import TaintRules, rules_for
from crucible.substrate.treesitter import get_tree, node_line, node_text


@dataclass
class _Func:
    name: str
    params: list[str]
    body: Any
    line: int


@dataclass
class Summary:
    # param name -> (rule_id, cwe, sink_line)
    sink_params: dict[str, tuple[str, str, int]] = field(default_factory=dict)
    return_params: set[str] = field(default_factory=set)
    return_uncond: bool = False

    def key(self) -> tuple:
        return (
            tuple(sorted(self.sink_params.items())),
            tuple(sorted(self.return_params)),
            self.return_uncond,
        )


@dataclass
class _Ctx:
    adapter: LanguageAdapter
    rules: TaintRules
    funcs: dict[str, _Func]
    summaries: dict[str, Summary]


def _basename(callee: str) -> str:
    return callee.rsplit(".", 1)[-1]


def analyze_source_interprocedural(
    source: str, language: str, *, path: str = "<memory>", taint_params: bool = False
) -> list[Finding]:
    """Inter-procedural taint. With ``taint_params=True`` each function's
    parameters are treated as attacker-controlled and findings record the entry
    function driven (used by the exploit prover to build a call that drives a
    whole chain). Default (False) uses only real sources, as scanning does."""
    adapter = adapter_for(language)
    rules = rules_for(language)
    if adapter is None or rules is None:
        return []
    root = get_tree(source, language).root_node
    funcs = _collect_funcs(root, adapter)
    ctx = _Ctx(adapter, rules, funcs, {name: Summary() for name in funcs})

    # Fixpoint over summaries (a function's summary may depend on callees').
    for _ in range(len(funcs) + 2):
        changed = False
        for name, fn in funcs.items():
            new = _build_summary(fn, ctx)
            if new.key() != ctx.summaries[name].key():
                ctx.summaries[name] = new
                changed = True
        if not changed:
            break

    # Main pass: emit findings (module scope + each function body).
    findings: list[Finding] = []
    _run_scope(root, {}, ctx, path, current=None, emit=findings, collect=None)
    for fn in funcs.values():
        seed = (
            {p: TaintMark(fn.line, "user", origin=p) for p in fn.params}
            if taint_params
            else {}
        )
        _run_scope(fn.body, seed, ctx, path, current=fn, emit=findings, collect=None)

    # Dedupe by (rule, sink line, source line).
    unique: dict[tuple, Finding] = {}
    for f in findings:
        src_line = f.evidence.get("taint", {}).get("path", [{}])[0].get("line")
        unique.setdefault((f.rule_id, f.location.start_line, src_line), f)
    return list(unique.values())


def _collect_funcs(root: Any, adapter: LanguageAdapter) -> dict[str, _Func]:
    funcs: dict[str, _Func] = {}
    stack = [root]
    while stack:
        node = stack.pop()
        for child in node.children:
            if adapter.is_function(child):
                name = adapter.function_name(child)
                body = adapter.function_body(child)
                if name is not None and body is not None:
                    funcs[name] = _Func(
                        name=name,
                        params=adapter.param_names(child),
                        body=body,
                        line=node_line(child),
                    )
            stack.append(child)
    return funcs


def _build_summary(fn: _Func, ctx: _Ctx) -> Summary:
    summary = Summary()
    tainted = {p: TaintMark(fn.line, "user", origin=p) for p in fn.params}
    _run_scope(fn.body, tainted, ctx, "<summary>", current=fn, emit=None, collect=summary)
    return summary


def _run_scope(
    scope: Any,
    tainted: dict[str, TaintMark],
    ctx: _Ctx,
    path: str,
    *,
    current: _Func | None,
    emit: list[Finding] | None,
    collect: Summary | None,
) -> None:
    a = ctx.adapter
    for node in _walk(scope, a):
        assignment = a.as_assignment(node)
        if assignment is not None:
            target, value = assignment
            mark = _expr_taint(value, tainted, ctx)
            if mark is not None and ctx.rules.assign_sinks.matches(node_text(target)):
                _hit(node, node_text(target), mark, ctx, path, current, emit, collect)
            name = a.identifier_name(target)
            if name is not None:
                if mark is not None:
                    tainted[name] = mark
                else:
                    tainted.pop(name, None)
            continue

        ret = a.as_return(node)
        if ret is not None and collect is not None and current is not None:
            mark = _expr_taint(ret, tainted, ctx)
            if mark is not None:
                if mark.origin in current.params:
                    collect.return_params.add(mark.origin)
                elif mark.origin is None:
                    collect.return_uncond = True
            continue

        call = a.as_call(node)
        if call is not None:
            callee, args = call
            if ctx.rules.sinks.matches(callee) and args:
                mark = _expr_taint(args[0], tainted, ctx)
                if mark is not None:
                    _hit(node, callee, mark, ctx, path, current, emit, collect)
            _check_local_call_sink(node, callee, args, tainted, ctx, path, current, emit, collect)


def _check_local_call_sink(
    call_node: Any,
    callee: str,
    args: list[Any],
    tainted: dict[str, TaintMark],
    ctx: _Ctx,
    path: str,
    current: _Func | None,
    emit: list[Finding] | None,
    collect: Summary | None,
) -> None:
    """A tainted argument passed to a local function whose summary says that
    parameter reaches a sink is a cross-function finding."""
    summ = ctx.summaries.get(_basename(callee))
    if summ is None or not summ.sink_params:
        return
    fn = ctx.funcs[_basename(callee)]
    for i, arg in enumerate(args):
        if i >= len(fn.params):
            break
        param = fn.params[i]
        if param not in summ.sink_params:
            continue
        mark = _expr_taint(arg, tainted, ctx)
        if mark is None:
            continue
        rule_id, cwe, sink_line = summ.sink_params[param]
        _hit_at(
            sink_line, rule_id, cwe, mark, callee, ctx, path, current, emit, collect,
            cross=True,
        )


def _expr_taint(node: Any, tainted: dict[str, TaintMark], ctx: _Ctx) -> TaintMark | None:
    a, rules = ctx.adapter, ctx.rules
    call = a.as_call(node)
    if call is not None:
        callee, args = call
        if rules.sanitizers.matches(callee):
            return None
        if rules.llm_sources.matches(callee):
            return TaintMark(node_line(node), "llm")
        if rules.sources.matches(callee):
            return TaintMark(node_line(node), "user")
        summ = ctx.summaries.get(_basename(callee))
        if summ is not None:
            # Known local function: use its summary precisely (no over-approx).
            if summ.return_uncond:
                return TaintMark(node_line(node), "user")
            fn = ctx.funcs[_basename(callee)]
            for i, arg in enumerate(args):
                if i < len(fn.params) and fn.params[i] in summ.return_params:
                    m = _expr_taint(arg, tainted, ctx)
                    if m is not None:
                        return m
            return None
        # unknown call: fall through to over-approximate via children (args)
    if node.type in a.access_types:
        text = node_text(node)
        if rules.llm_sources.matches(text):
            return TaintMark(node_line(node), "llm")
        if rules.sources.matches(text):
            return TaintMark(node_line(node), "user")
    name = a.identifier_name(node)
    if name is not None:
        return tainted.get(name)
    if a.is_string_literal(node):
        return None
    best: TaintMark | None = None
    for child in node.children:
        m = _expr_taint(child, tainted, ctx)
        if m is not None and (best is None or m.line < best.line):
            best = m
    return best


def _walk(scope: Any, adapter: LanguageAdapter):
    for child in scope.children:
        if adapter.is_function(child):
            continue
        yield child
        yield from _walk(child, adapter)


def _hit(
    sink_node: Any,
    sink_text: str,
    mark: TaintMark,
    ctx: _Ctx,
    path: str,
    current: _Func | None,
    emit: list[Finding] | None,
    collect: Summary | None,
) -> None:
    rule_id, cwe = ctx.rules.label_for(sink_text)
    _hit_at(
        node_line(sink_node), rule_id, cwe, mark, sink_text, ctx, path, current,
        emit, collect, cross=False,
    )


def _hit_at(
    sink_line: int,
    rule_id: str,
    cwe: str,
    mark: TaintMark,
    sink_text: str,
    ctx: _Ctx,
    path: str,
    current: _Func | None,
    emit: list[Finding] | None,
    collect: Summary | None,
    *,
    cross: bool,
) -> None:
    # Summary mode: record which current-function parameter reaches this sink.
    if collect is not None:
        if mark.origin is not None and current is not None:
            collect.sink_params[mark.origin] = (rule_id, cwe, sink_line)
        return
    if emit is None:
        return
    final_rule = rule_id
    if mark.kind == "llm":
        final_rule = "crucible.insecure-llm-output-handling"
        message = f"LLM output reaches {sink_text} without validation"
    else:
        message = f"tainted data reaches {sink_text} without sanitization"
    if cross:
        message += " (flow crosses a function boundary)"
    finding = Finding(
        rule_id=final_rule,
        message=message,
        severity=Severity.HIGH,
        location=Location(path=path, start_line=sink_line),
        source="crucible-taint-interproc" if cross else "crucible-taint",
        cwe=cwe,
    )
    hops = [{"role": "source", "line": mark.line, "kind": mark.kind}]
    if cross:
        hops.append({"role": "call", "sink_function": _basename(sink_text)})
    hops.append({"role": "sink", "line": sink_line, "target": sink_text})
    finding.evidence["taint"] = {
        "reachable": True,
        "source_kind": mark.kind,
        "interprocedural": cross,
        "path": hops,
    }
    if final_rule in EXECUTION_SINK_RULES and mark.origin is not None:
        exploit = {"param": mark.origin, "sink_class": final_rule}
        if current is not None:
            # The entry function to drive: passing a payload as ``param`` here
            # reaches the execution sink (possibly through other local calls).
            exploit["function"] = current.name
        finding.evidence["exploit"] = exploit
    emit.append(finding)
