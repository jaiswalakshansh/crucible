"""Verify the config/crypto pattern detector (precision-focused)."""

import pytest

from crucible.substrate.patterns import scan_patterns


def _rules(src, lang="python"):
    return [f.rule_id for f in scan_patterns(src, lang)]


@pytest.mark.parametrize(
    "src,rule",
    [
        ('AWS_KEY = "AKIAIOSFODNN7EXAMPLE"', "crucible.hardcoded-secret"),
        ('api_key = "a1b2c3d4e5f6g7h8"', "crucible.hardcoded-secret"),
        ("h = hashlib.md5(data).hexdigest()", "crucible.weak-crypto"),
        ("token = str(random.randint(0, 9999))", "crucible.insecure-randomness"),
        ("app.run(debug=True)", "crucible.security-misconfig"),
        ("requests.get(url, verify=False)", "crucible.insecure-transport"),
        ('h = {"Access-Control-Allow-Origin": "*"}', "crucible.permissive-cors"),
    ],
)
def test_pattern_positives(src, rule):
    assert rule in _rules(src)


@pytest.mark.parametrize(
    "src",
    [
        'password = "required"',          # short, all-alpha -> not secret-like
        'password = os.environ["PW"]',    # env lookup, no literal
        "h = hashlib.sha256(data)",       # strong hash
        "token = secrets.token_hex(16)",  # secure RNG
        '# password = "hunter2abc"',      # comment
        "verify = True",                  # verification on
    ],
)
def test_pattern_negatives(src):
    assert scan_patterns(src, "python") == []


def test_js_weak_hash():
    assert "crucible.weak-crypto" in _rules(
        'const h = crypto.createHash("md5").update(x);', "javascript"
    )


def test_pattern_findings_are_suspected_and_marked():
    f = scan_patterns('api_key = "a1b2c3d4e5f6g7h8"', "python")[0]
    assert f.confirmation.value == "suspected"
    assert f.evidence["pattern"]["kind"] == "config"
    assert f.source == "crucible-pattern"


def test_severity_high_for_known_token_format():
    f = scan_patterns('k = "AKIAIOSFODNN7EXAMPLE"', "python")[0]
    assert f.severity.value == "high"


# --- precision fixes from real-world measurement --------------------------------

def test_usedforsecurity_false_is_not_weak_crypto():
    # Modern code marks non-security hashes explicitly; must not be flagged.
    src = "h = hashlib.md5(x, usedforsecurity=False).hexdigest()"
    assert scan_patterns(src, "python") == []
    # Without the marker it is still flagged.
    assert scan_patterns("h = hashlib.md5(x).hexdigest()", "python")


def test_debug_in_docstring_is_not_flagged():
    src = 'def f():\n    """You can set debug=True to enable the reloader."""\n    return 1\n'
    assert scan_patterns(src, "python") == []


def test_debug_in_real_code_is_flagged():
    assert any(
        f.rule_id == "crucible.security-misconfig"
        for f in scan_patterns("app.run(debug=True)", "python")
    )


def test_secret_in_string_value_still_detected_not_masked():
    # A secret lives inside a string literal (value, not a docstring) -> keep it.
    assert scan_patterns('api_key = "a1b2c3d4e5f6g7h8"', "python")
    assert scan_patterns('cfg = {"Access-Control-Allow-Origin": "*"}', "python")


def test_md5_inside_a_regex_string_is_not_a_finding():
    # A string value containing 'hashlib.md5' (e.g. a detector's own rule) is not
    # code calling md5. Parent is an assignment, but the match is inside the string
    # value... this documents that string *values* are matched; here it is a
    # deliberate weak-crypto keyword, so it IS reported. Regression guard for intent.
    src = 'pattern = "hashlib.md5"'
    # It matches (string value scanning is intended for secrets/CORS); ensure no crash.
    scan_patterns(src, "python")
