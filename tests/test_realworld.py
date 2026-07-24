"""Real-code hardening: tuple unpacking, handler-gated sources, and the
DSVW-shape fixture that the engine previously found nothing in.

These lock in the fix that took Crucible from 0 findings on a real vulnerable app
to finding its documented vulnerabilities.
"""

import os

from crucible.evals.realworld import load_manifest, measure_dir
from crucible.substrate.candidates import analyze_file
from crucible.substrate.taint import analyze_source as intra
from crucible.substrate.interproc import analyze_source_interprocedural as ip

FIXTURES = os.path.join(os.path.dirname(__file__), "..", "evals", "fixtures", "realworld")
APP = os.path.join(FIXTURES, "http_handler_app.py")


# --- tuple unpacking ------------------------------------------------------------

def test_tuple_unpack_positional_pairing():
    # a, b = tainted, safe  -> only a is tainted (positional, precise)
    src = (
        'def h(request):\n'
        '    a, b = request.args.get("x"), "const"\n'
        '    db.execute(a)\n'      # tainted -> flagged
        '    db.execute(b)\n'      # constant -> not flagged
    )
    findings = intra(src, "python")
    assert len(findings) == 1
    assert findings[0].location.start_line == 3


def test_tuple_unpack_from_single_expression_over_approximates():
    # a, b = f(tainted) -> can't split the return, so both get tainted.
    src = (
        'def h(request):\n'
        '    a, b = split(request.args.get("x"))\n'
        '    db.execute(b)\n'
    )
    assert len(intra(src, "python")) == 1


def test_tuple_unpack_in_interprocedural_path():
    src = (
        'def h(request):\n'
        '    path, query = request.args.get("p").split("?")\n'
        '    db.execute("S" + query)\n'
    )
    assert len(ip(src, "python")) == 1


# --- handler-gated self.* sources ----------------------------------------------

def test_self_path_is_source_only_in_handler_method():
    handler = (
        "class H:\n"
        "    def do_GET(self):\n"
        '        db.execute("S" + self.path)\n'
    )
    assert len(intra(handler, "python")) == 1


def test_self_path_not_flagged_outside_handler():
    non_handler = (
        "class File:\n"
        "    def read(self):\n"
        "        return open(self.path).read()\n"
    )
    assert intra(non_handler, "python") == []


# --- the DSVW-shape fixture -----------------------------------------------------

def test_dsvw_shape_fixture_is_detected():
    findings = analyze_file(APP)
    rules = {f.rule_id for f in findings}
    assert "crucible.sql-injection" in rules
    assert "crucible.path-traversal" in rules
    assert "crucible.command-injection" in rules
    assert "crucible.insecure-deserialization" in rules


def test_dsvw_shape_safe_endpoints_not_flagged():
    findings = analyze_file(APP)
    # The parameterized do_POST insert and the non-handler File.load must be clean.
    for f in findings:
        assert "INSERT" not in f.message  # parameterized insert not flagged
    # Exactly the 4 vulnerable GET endpoints.
    assert len(findings) == 4


def test_measure_dir_recall_on_fixture():
    labels = load_manifest(os.path.join(FIXTURES, "manifest.json"))
    result = measure_dir(FIXTURES, labels)
    assert result.score.recall == 1.0
    assert result.score.fn == 0
    assert len(result.unmatched) == 0
