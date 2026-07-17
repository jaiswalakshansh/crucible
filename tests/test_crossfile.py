"""Verify cross-file (import-resolved) inter-procedural taint."""

import os

from crucible.substrate.candidates import taint_candidates
from crucible.substrate.interproc import analyze_project

FIXTURES = os.path.join(os.path.dirname(__file__), "..", "evals", "fixtures", "crossfile")


def test_from_import_flow_crosses_files():
    files = {
        "app.py": (
            "from db import run_query\n"
            "def handler(request):\n"
            '    run_query(request.args.get("id"))\n'
        ),
        "db.py": "def run_query(q):\n    conn.execute('SELECT ' + q)\n",
    }
    findings = analyze_project(files)
    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "crucible.sql-injection"
    # The finding is located at the sink, in the OTHER file.
    assert f.location.path == "db.py"
    assert f.evidence["taint"]["interprocedural"] is True


def test_import_module_dotted_call():
    files = {
        "app.py": (
            "import helpers\n"
            "def handler(request):\n"
            '    helpers.ping(request.args.get("host"))\n'
        ),
        "helpers.py": "import os\ndef ping(h):\n    os.system('ping ' + h)\n",
    }
    findings = analyze_project(files)
    assert len(findings) == 1
    assert findings[0].rule_id == "crucible.command-injection"
    assert findings[0].location.path == "helpers.py"


def test_aliased_import():
    files = {
        "app.py": (
            "from db import run_query as rq\n"
            "def handler(request):\n"
            '    rq(request.args.get("id"))\n'
        ),
        "db.py": "def run_query(q):\n    conn.execute('SELECT ' + q)\n",
    }
    assert len(analyze_project(files)) == 1


def test_cross_file_parameterized_is_safe():
    files = {
        "app.py": (
            "from db import run_query\n"
            "def handler(request):\n"
            '    run_query(request.args.get("id"))\n'
        ),
        "db.py": "def run_query(q):\n    conn.execute('SELECT ?', (q,))\n",
    }
    assert analyze_project(files) == []


def test_return_taint_across_files():
    files = {
        "src.py": "def read(request):\n    return request.args.get('id')\n",
        "app.py": (
            "from src import read\n"
            "def handler(request):\n"
            "    x = read(request)\n"
            "    conn.execute('S' + x)\n"
        ),
    }
    findings = analyze_project(files)
    assert len(findings) == 1
    assert findings[0].location.path == "app.py"  # sink is in app.py


def test_unresolved_import_does_not_crash_or_falsely_flag():
    # Importing from a module not in the set: no resolution, no finding, no error.
    files = {
        "app.py": (
            "from external_lib import run_query\n"
            "def handler(request):\n"
            '    run_query(request.args.get("id"))\n'
        ),
    }
    assert analyze_project(files) == []


def test_taint_candidates_directory_uses_cross_file():
    vuln = taint_candidates(os.path.join(FIXTURES, "vuln"))
    assert any(f.rule_id == "crucible.sql-injection" for f in vuln)
    assert any(f.location.path.endswith("db.py") for f in vuln)

    safe = taint_candidates(os.path.join(FIXTURES, "safe"))
    assert safe == []


def test_non_python_falls_back_to_per_file():
    # JS is not cross-file resolved; a single-file JS flow still works.
    files = {"a.js": 'function h(req){ db.query("S" + req.query.id); }'}
    findings = analyze_project(files, language="javascript")
    assert len(findings) == 1
