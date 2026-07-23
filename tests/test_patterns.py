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
