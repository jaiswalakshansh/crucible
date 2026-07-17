"""Inter-procedural taint via function summaries.

Works within a file and, for Python, across files in a project via import
resolution. The intra-procedural analyzer misses the common shape where a handler
passes input to a helper that hits the sink; this closes that gap, and the
cross-file path extends it to helpers defined in other modules.

Approach (standard summary-based dataflow):

1. Collect every named function (across all files, keyed by ``module:name``).
2. Compute a summary per function to a fixpoint:
   - ``sink_params``: parameters that, if tainted, reach a sink (directly or via a
     call to another function whose summary says so). Each records the sink's rule,
     CWE, line, and *file* (so cross-file findings point at the right place).
   - ``return_params`` / ``return_uncond``: parameter- and internal-source-driven
     return taint.
3. Main pass: analyze each function with real sources; at a call, resolve the
   callee (locally, or through the file's imports) and consult its summary.

Honest limits:
- **Cross-file resolution is Python-only and filename-based.** ``from helpers
  import f`` / ``import helpers`` resolve to a file whose stem is ``helpers``.
  Package paths and dotted modules match on the last segment (collisions resolve to
  one definition). Star imports and dynamic imports are not resolved.
- **Positional arguments only.** Document-order and control-flow limits of the
  intra analyzer still apply.
- The result is a superset of intra-procedural findings (never loses one).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Callable

from crucible.schema.finding import Finding, Location, Severity
from crucible.substrate.adapters import LanguageAdapter, adapter_for
from crucible.substrate.taint import EXECUTION_SINK_RULES, TaintMark
from crucible.substrate.taint_rules import TaintRules, rules_for
from crucible.substrate.treesitter import get_tree, node_line, node_text


@dataclass
class _Func:
    qid: str  # "module:name"
    module: str
    name: str
    params: list[str]
    body: Any
    path: str


@dataclass
class Summary:
    # param -> (rule_id, cwe, sink_line, sink_path)
    sink_params: dict[str, tuple[str, str, int, str]] = field(default_factory=dict)
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
    resolve: Callable[[str, str], str | None]  # (callee_text, current_module) -> qid
    current_module: str = ""


def _basename(callee: str) -> str:
    return callee.rsplit(".", 1)[-1]


# ---------------------------------------------------------------------------
# Public entry points
# ---------------------------------------------------------------------------

def analyze_source_interprocedural(
    source: str, language: str, *, path: str = "<memory>", taint_params: bool = False
) -> list[Finding]:
    """Single-file inter-procedural taint (any supported language)."""
    adapter = adapter_for(language)
    rules = rules_for(language)
    if adapter is None or rules is None:
        return []
    root = get_tree(source, language).root_node
    funcs = _collect_funcs(root, adapter, module="", path=path)

    def resolve(callee: str, _module: str) -> str | None:
        qid = f":{_basename(callee)}"
        return qid if qid in funcs else None

    ctx = _Ctx(adapter, rules, funcs, {q: Summary() for q in funcs}, resolve)
    _fixpoint(ctx)
    return _main_pass(ctx, {"": root}, taint_params)


def analyze_project(
    files: dict[str, str], *, language: str = "python"
) -> list[Finding]:
    """Cross-file inter-procedural taint over a set of ``path -> source`` files.

    Only Python is supported for cross-file resolution; for other languages this
    falls back to analyzing each file independently."""
    adapter = adapter_for(language)
    rules = rules_for(language)
    if adapter is None or rules is None:
        return []
    if language != "python":
        out: list[Finding] = []
        for path, source in files.items():
            out.extend(analyze_source_interprocedural(source, language, path=path))
        return out

    roots: dict[str, Any] = {}
    funcs: dict[str, _Func] = {}
    from_imports: dict[str, dict[str, tuple[str, str]]] = {}
    module_aliases: dict[str, dict[str, str]] = {}

    for path, source in files.items():
        module = _module_stem(path)
        root = get_tree(source, language).root_node
        roots[module] = root
        funcs.update(_collect_funcs(root, adapter, module=module, path=path))
        fi, ma = _parse_imports(source)
        from_imports[module] = fi
        module_aliases[module] = ma

    def resolve(callee: str, current: str) -> str | None:
        if "." not in callee:
            local = f"{current}:{callee}"
            if local in funcs:
                return local
            target = from_imports.get(current, {}).get(callee)
            if target is not None:
                qid = f"{target[0]}:{target[1]}"
                return qid if qid in funcs else None
            return None
        prefix, name = callee.rsplit(".", 1)
        stem = module_aliases.get(current, {}).get(prefix)
        if stem is not None:
            qid = f"{stem}:{name}"
            return qid if qid in funcs else None
        return None

    ctx = _Ctx(adapter, rules, funcs, {q: Summary() for q in funcs}, resolve)
    _fixpoint(ctx)
    return _main_pass(ctx, roots, taint_params=False)


# ---------------------------------------------------------------------------
# Collection & imports
# ---------------------------------------------------------------------------

def _module_stem(path: str) -> str:
    base = path.rsplit("/", 1)[-1]
    return base[:-3] if base.endswith(".py") else base


def _collect_funcs(
    root: Any, adapter: LanguageAdapter, *, module: str, path: str
) -> dict[str, _Func]:
    funcs: dict[str, _Func] = {}
    stack = [root]
    while stack:
        node = stack.pop()
        for child in node.children:
            if adapter.is_function(child):
                name = adapter.function_name(child)
                body = adapter.function_body(child)
                if name is not None and body is not None:
                    qid = f"{module}:{name}"
                    funcs[qid] = _Func(
                        qid=qid,
                        module=module,
                        name=name,
                        params=adapter.param_names(child),
                        body=body,
                        path=path,
                    )
            stack.append(child)
    return funcs


_FROM_RE = re.compile(r"^\s*from\s+(\.*[\w.]*)\s+import\s+(.+?)\s*$")
_IMPORT_RE = re.compile(r"^\s*import\s+(.+?)\s*$")


def _parse_imports(
    source: str,
) -> tuple[dict[str, tuple[str, str]], dict[str, str]]:
    """Parse Python imports. Returns (from_imports, module_aliases):
    - from_imports: local_name -> (target_module_stem, original_name)
    - module_aliases: alias_or_name -> target_module_stem
    Line-based; handles the common single-line forms."""
    from_imports: dict[str, tuple[str, str]] = {}
    module_aliases: dict[str, str] = {}
    for line in source.splitlines():
        m = _FROM_RE.match(line)
        if m:
            module, names = m.group(1), m.group(2)
            stem = module.strip(".").rsplit(".", 1)[-1]
            relative = module.startswith(".") and not stem
            for part in names.split(","):
                part = part.strip().strip("()")
                if not part or part == "*":
                    continue
                toks = part.split()
                orig = toks[0]
                local = toks[2] if len(toks) >= 3 and toks[1] == "as" else orig
                if relative:
                    # ``from . import helpers`` -> ``helpers`` names a module.
                    module_aliases[local] = orig
                else:
                    from_imports[local] = (stem, orig)
            continue
        m = _IMPORT_RE.match(line)
        if m and not line.lstrip().startswith("import ("):
            for part in m.group(1).split(","):
                part = part.strip()
                if not part:
                    continue
                toks = part.split()
                mod = toks[0]
                alias = toks[2] if len(toks) >= 3 and toks[1] == "as" else mod
                module_aliases[alias] = mod.rsplit(".", 1)[-1]
    return from_imports, module_aliases


# ---------------------------------------------------------------------------
# Fixpoint & passes
# ---------------------------------------------------------------------------

def _fixpoint(ctx: _Ctx) -> None:
    for _ in range(len(ctx.funcs) + 2):
        changed = False
        for qid, fn in ctx.funcs.items():
            new = _build_summary(fn, ctx)
            if new.key() != ctx.summaries[qid].key():
                ctx.summaries[qid] = new
                changed = True
        if not changed:
            break


def _build_summary(fn: _Func, ctx: _Ctx) -> Summary:
    summary = Summary()
    ctx.current_module = fn.module
    tainted = {p: TaintMark(0, "user", origin=p) for p in fn.params}
    _run_scope(fn.body, tainted, ctx, fn.path, current=fn, emit=None, collect=summary)
    return summary


def _main_pass(
    ctx: _Ctx, roots: dict[str, Any], taint_params: bool
) -> list[Finding]:
    findings: list[Finding] = []
    for module, root in roots.items():
        ctx.current_module = module
        _run_scope(root, {}, ctx, _path_for(ctx, module), current=None, emit=findings, collect=None)
    for fn in ctx.funcs.values():
        ctx.current_module = fn.module
        seed = (
            {p: TaintMark(0, "user", origin=p) for p in fn.params}
            if taint_params
            else {}
        )
        _run_scope(fn.body, seed, ctx, fn.path, current=fn, emit=findings, collect=None)

    unique: dict[tuple, Finding] = {}
    for f in findings:
        src_line = f.evidence.get("taint", {}).get("path", [{}])[0].get("line")
        unique.setdefault((f.rule_id, f.location.path, f.location.start_line, src_line), f)
    return list(unique.values())


def _path_for(ctx: _Ctx, module: str) -> str:
    for fn in ctx.funcs.values():
        if fn.module == module:
            return fn.path
    return module or "<memory>"


# ---------------------------------------------------------------------------
# Core scope analysis (shared by summary and main passes)
# ---------------------------------------------------------------------------

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
            _check_resolved_call_sink(callee, args, tainted, ctx, current, emit, collect)


def _check_resolved_call_sink(
    callee: str,
    args: list[Any],
    tainted: dict[str, TaintMark],
    ctx: _Ctx,
    current: _Func | None,
    emit: list[Finding] | None,
    collect: Summary | None,
) -> None:
    qid = ctx.resolve(callee, ctx.current_module)
    if qid is None:
        return
    summ = ctx.summaries.get(qid)
    if summ is None or not summ.sink_params:
        return
    fn = ctx.funcs[qid]
    for i, arg in enumerate(args):
        if i >= len(fn.params):
            break
        param = fn.params[i]
        if param not in summ.sink_params:
            continue
        mark = _expr_taint(arg, tainted, ctx)
        if mark is None:
            continue
        rule_id, cwe, sink_line, sink_path = summ.sink_params[param]
        _emit_finding(
            sink_line, sink_path, rule_id, cwe, mark, fn.name, ctx, current,
            emit, collect, cross=True,
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
        qid = ctx.resolve(callee, ctx.current_module)
        if qid is not None:
            summ = ctx.summaries.get(qid)
            if summ is not None:
                if summ.return_uncond:
                    return TaintMark(node_line(node), "user")
                fn = ctx.funcs[qid]
                for i, arg in enumerate(args):
                    if i < len(fn.params) and fn.params[i] in summ.return_params:
                        m = _expr_taint(arg, tainted, ctx)
                        if m is not None:
                            return m
                return None
        # unknown call: over-approximate via children (args)
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
    _emit_finding(
        node_line(sink_node), path, rule_id, cwe, mark, sink_text, ctx, current,
        emit, collect, cross=False,
    )


def _emit_finding(
    sink_line: int,
    sink_path: str,
    rule_id: str,
    cwe: str,
    mark: TaintMark,
    sink_text: str,
    ctx: _Ctx,
    current: _Func | None,
    emit: list[Finding] | None,
    collect: Summary | None,
    *,
    cross: bool,
) -> None:
    if collect is not None:
        if mark.origin is not None and current is not None:
            collect.sink_params[mark.origin] = (rule_id, cwe, sink_line, sink_path)
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
        location=Location(path=sink_path, start_line=sink_line),
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
            exploit["function"] = current.name
        finding.evidence["exploit"] = exploit
    emit.append(finding)
