"""Verify the tree-sitter taint analyzer on real code (real parsing, no mocks)."""

import pytest

from crucible.substrate.taint import analyze_source


def _lines(findings):
    return sorted(f.location.start_line for f in findings)


# --- Python true positives ------------------------------------------------------

def test_py_direct_source_to_sink():
    src = 'def h(request):\n    db.execute(request.args.get("id"))\n'
    f = analyze_source(src, "python")
    assert len(f) == 1
    assert f[0].rule_id == "crucible.sql-injection"
    assert f[0].cwe == "CWE-89"


def test_py_taint_through_variable_and_concat():
    src = (
        'def h(request):\n'
        '    uid = request.args.get("id")\n'
        '    q = "SELECT " + uid\n'
        '    db.execute(q)\n'
    )
    f = analyze_source(src, "python")
    assert _lines(f) == [4]  # reported at the sink line


def test_py_subscript_source():
    src = 'def h(request):\n    db.execute(request.args["id"])\n'
    assert len(analyze_source(src, "python")) == 1


def test_py_command_injection():
    src = 'import os\ndef h(request):\n    os.system("ping " + request.args.get("h"))\n'
    f = analyze_source(src, "python")
    assert f[0].rule_id == "crucible.command-injection"
    assert f[0].cwe == "CWE-78"


def test_py_eval_code_injection():
    src = 'def h(request):\n    eval(request.args.get("x"))\n'
    assert analyze_source(src, "python")[0].rule_id == "crucible.code-injection"


# --- Python true negatives (precision) ------------------------------------------

def test_py_parameterized_query_is_safe():
    src = (
        'def h(request):\n'
        '    uid = request.args.get("id")\n'
        '    db.execute("SELECT * WHERE id = ?", (uid,))\n'
    )
    assert analyze_source(src, "python") == []


def test_py_sanitized_by_int_is_safe():
    src = (
        'def h(request):\n'
        '    uid = int(request.args.get("id"))\n'
        '    db.execute("SELECT " + str(uid))\n'
    )
    assert analyze_source(src, "python") == []


def test_py_constant_query_is_safe():
    assert analyze_source('def h():\n    db.execute("SELECT 1")\n', "python") == []


def test_py_reassignment_clears_taint():
    src = (
        'def h(request):\n'
        '    x = request.args.get("id")\n'
        '    x = "safe"\n'
        '    db.execute(x)\n'
    )
    assert analyze_source(src, "python") == []


def test_py_parameter_untainted_by_default():
    # A bare parameter is not treated as a source unless taint_params=True.
    src = 'def h(x):\n    db.execute(x)\n'
    assert analyze_source(src, "python") == []
    assert len(analyze_source(src, "python", taint_params=True)) == 1


def test_py_scopes_do_not_bleed():
    # taint in one function must not affect another.
    src = (
        'def a(request):\n'
        '    t = request.args.get("id")\n'
        'def b():\n'
        '    db.execute(t)\n'  # different scope: t is not tainted here
    )
    assert analyze_source(src, "python") == []


# --- JavaScript / TypeScript ----------------------------------------------------

def test_js_property_source_to_sink():
    src = 'function h(req){ let id=req.query.id; db.query("SELECT "+id); }'
    assert len(analyze_source(src, "javascript")) == 1


def test_js_constant_is_safe():
    assert analyze_source('function h(){ db.query("SELECT 1"); }', "javascript") == []


def test_ts_uses_same_analysis():
    src = 'function h(req: any){ db.query("SELECT " + req.query.id); }'
    assert len(analyze_source(src, "typescript")) == 1


# --- Graceful degradation -------------------------------------------------------

def test_unsupported_language_returns_empty_not_error():
    # Go parses but has no taint adapter yet -> no findings, no crash.
    assert analyze_source("package m\nfunc f(){}", "go") == []


def test_taint_finding_carries_reachability_evidence():
    src = 'def h(request):\n    db.execute(request.args.get("id"))\n'
    f = analyze_source(src, "python")[0]
    assert f.evidence["taint"]["reachable"] is True
    roles = [hop["role"] for hop in f.evidence["taint"]["path"]]
    assert roles == ["source", "sink"]


@pytest.mark.parametrize("lang", ["python", "javascript", "typescript"])
def test_supported_languages_parse_without_error(lang):
    # Smoke: analysis runs on trivial input for each supported language.
    analyze_source("x = 1\n" if lang == "python" else "var x = 1;", lang)


# --- Backend coverage: SSRF, path traversal, SSTI -------------------------------

def test_py_ssrf():
    src = 'import requests\ndef h(request):\n    requests.get(request.args.get("url"))\n'
    f = analyze_source(src, "python")
    assert f[0].rule_id == "crucible.ssrf"
    assert f[0].cwe == "CWE-918"


def test_py_path_traversal_and_sanitizer():
    vuln = 'def h(request):\n    open(request.args.get("f"))\n'
    assert analyze_source(vuln, "python")[0].rule_id == "crucible.path-traversal"
    safe = (
        'import os\n'
        'def h(request):\n'
        '    open(os.path.basename(request.args.get("f")))\n'
    )
    assert analyze_source(safe, "python") == []


def test_py_ssti():
    src = 'def h(request):\n    render_template_string(request.args.get("t"))\n'
    assert analyze_source(src, "python")[0].rule_id == "crucible.ssti"


# --- Frontend coverage: DOM XSS (assignment and call sinks) ---------------------

def test_js_dom_xss_assignment_sink():
    # el.innerHTML = tainted  -> assignment-target sink (new engine feature).
    src = "function h(){ el.innerHTML = location.hash; }"
    f = analyze_source(src, "javascript")
    assert f[0].rule_id == "crucible.dom-xss"
    assert f[0].cwe == "CWE-79"


def test_js_dom_xss_through_variable():
    src = "function h(){ let x = location.search; el.innerHTML = x; }"
    assert analyze_source(src, "javascript")[0].rule_id == "crucible.dom-xss"


def test_js_dom_xss_call_sink():
    assert (
        analyze_source("function h(){ document.write(document.URL); }", "javascript")[0].rule_id
        == "crucible.dom-xss"
    )


def test_js_dom_static_assignment_is_safe():
    assert analyze_source('function h(){ el.innerHTML = "static"; }', "javascript") == []


# --- AI/LLM coverage: insecure output handling ----------------------------------

def test_py_insecure_llm_output_into_eval():
    src = (
        'def h(client):\n'
        '    r = client.messages.create(x)\n'
        '    eval(r.content[0].text)\n'
    )
    f = analyze_source(src, "python")
    assert f[0].rule_id == "crucible.insecure-llm-output-handling"
    assert f[0].evidence["taint"]["source_kind"] == "llm"


def test_py_insecure_llm_output_into_sql():
    src = (
        'def h(client, db):\n'
        '    out = client.chat.completions.create(x)\n'
        '    db.execute(out.choices[0].message.content)\n'
    )
    assert (
        analyze_source(src, "python")[0].rule_id
        == "crucible.insecure-llm-output-handling"
    )


def test_js_insecure_llm_output():
    src = "function h(c){ let r = c.messages.create(x); eval(r.content); }"
    assert (
        analyze_source(src, "javascript")[0].rule_id
        == "crucible.insecure-llm-output-handling"
    )


def test_source_kind_is_recorded_in_evidence():
    user = analyze_source('def h(request):\n    eval(request.args.get("x"))\n', "python")[0]
    assert user.evidence["taint"]["source_kind"] == "user"
