"""Verify inter-procedural taint on real cross-function code.

The central claim: flows that cross a function boundary — missed entirely by the
intra-procedural analyzer — are found, while precision is preserved (parameterized
/ constant cross-function calls are not flagged).
"""

import os

from crucible.evals.harness import load_fixture, run_eval
from crucible.substrate.candidates import analyze_file
from crucible.substrate.interproc import analyze_source_interprocedural as ip
from crucible.substrate.taint import analyze_source as intra

CORPUS = os.path.join(os.path.dirname(__file__), "..", "evals", "fixtures", "interproc")


def _rules(findings):
    return sorted(f.rule_id for f in findings)


def test_cross_function_sink_is_found_and_intra_misses_it():
    src = (
        "def handler(request):\n"
        '    data = request.args.get("id")\n'
        "    run_query(data)\n"
        "def run_query(q):\n"
        '    db.execute("SELECT " + q)\n'
    )
    assert intra(src, "python") == []  # intra-procedural is blind to this
    found = ip(src, "python")
    assert len(found) == 1
    assert found[0].rule_id == "crucible.sql-injection"
    assert found[0].evidence["taint"]["interprocedural"] is True


def test_cross_function_parameterized_is_safe():
    src = (
        "def handler(request):\n"
        '    data = request.args.get("id")\n'
        "    run_query(data)\n"
        "def run_query(q):\n"
        '    db.execute("SELECT ?", (q,))\n'
    )
    assert ip(src, "python") == []


def test_return_taint_across_function():
    src = (
        "def get_input(request):\n"
        '    return request.args.get("id")\n'
        "def handler(request):\n"
        "    x = get_input(request)\n"
        '    db.execute("S" + x)\n'
    )
    assert intra(src, "python") == []
    assert len(ip(src, "python")) == 1


def test_two_hop_flow():
    src = (
        "import os\n"
        "def handler(request):\n"
        '    a(request.args.get("id"))\n'
        "def a(x):\n"
        "    b(x)\n"
        "def b(y):\n"
        '    os.system("ping " + y)\n'
    )
    found = ip(src, "python")
    assert len(found) == 1
    assert found[0].rule_id == "crucible.command-injection"


def test_constant_argument_does_not_flow():
    src = (
        "def handler(request):\n"
        '    run_query("constant")\n'
        "def run_query(q):\n"
        '    db.execute("SELECT " + q)\n'
    )
    assert ip(src, "python") == []


def test_recursion_terminates():
    # A self-recursive function must not hang the fixpoint or the walk.
    src = (
        "def f(request):\n"
        '    x = request.args.get("id")\n'
        "    f(x)\n"
        '    db.execute(x)\n'
    )
    found = ip(src, "python")
    assert any(f.rule_id == "crucible.sql-injection" for f in found)


def test_interproc_is_superset_of_intra_on_single_function():
    # Existing single-function findings must still be present.
    src = 'def h(request):\n    db.execute("S" + request.args.get("id"))\n'
    intra_lines = {f.location.start_line for f in intra(src, "python")}
    ip_lines = {f.location.start_line for f in ip(src, "python")}
    assert intra_lines and intra_lines.issubset(ip_lines)


def test_corpus_scores_perfect_on_cross_function_set():
    cases = load_fixture(CORPUS)
    result = run_eval(cases, analyze_file, root=CORPUS)
    assert result.overall.fp == 0
    assert result.overall.fn == 0
    assert result.overall.precision == 1.0
    assert result.overall.recall == 1.0
