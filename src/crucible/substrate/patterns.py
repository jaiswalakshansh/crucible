"""Pattern detector for configuration/crypto weaknesses.

These classes are NOT data-flow problems — they are single-point properties of the
code (a weak hash call, a hardcoded credential, ``debug=True``). The taint engine
structurally cannot find them, so this is a separate, deliberately simple
line/regex detector. Findings are reported as ``suspected`` like any other; they
carry ``evidence['pattern']`` to make clear they came from a point match, not a
traced flow.

Precision is the priority: generic hardcoded-secret matching requires the value to
look secret-like (has a digit, or is long, or matches a known token format) to
avoid flagging strings like ``password = "required"``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable

from crucible.schema.finding import Finding, Location, Severity


@dataclass(frozen=True)
class PatternRule:
    rule_id: str
    cwe: str
    severity: Severity
    regex: re.Pattern
    message: str
    languages: frozenset[str]  # empty = all supported languages
    # Optional check on regex capture group 1 (e.g. a secret value must look
    # secret-like). If it returns False the match is discarded.
    value_check: Callable[[str], bool] | None = None


def _looks_secret(value: str) -> bool:
    return any(c.isdigit() for c in value) or len(value) >= 16


_SECRET_NAME = r"(?i)(pass(?:word|wd)?|secret|api[_-]?key|access[_-]?key|auth[_-]?token|token)"
# Value looks secret-like: has a digit, or is long, or is a known token format.
_SECRET_VALUE = r"""['"]([A-Za-z0-9_\-./+=]{8,})['"]"""

_KNOWN_TOKENS = re.compile(
    r"(AKIA[0-9A-Z]{16}"           # AWS access key id
    r"|ghp_[A-Za-z0-9]{20,}"       # GitHub personal token
    r"|gho_[A-Za-z0-9]{20,}"
    r"|xox[baprs]-[A-Za-z0-9-]{10,}"  # Slack
    r"|AIza[0-9A-Za-z_\-]{20,}"    # Google API key
    r"|-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----)"  # private keys
)


RULES: list[PatternRule] = [
    PatternRule(
        "crucible.hardcoded-secret", "CWE-798", Severity.HIGH,
        _KNOWN_TOKENS,
        "hardcoded credential / private key (known token format)",
        frozenset(),
    ),
    PatternRule(
        "crucible.hardcoded-secret", "CWE-798", Severity.MEDIUM,
        re.compile(_SECRET_NAME + r"\s*[=:]\s*" + _SECRET_VALUE),
        "possible hardcoded secret assigned to a credential-named variable",
        frozenset(),
        value_check=_looks_secret,
    ),
    PatternRule(
        "crucible.weak-crypto", "CWE-327", Severity.MEDIUM,
        re.compile(r"hashlib\.(md5|sha1)\s*\(|\bDES\.new\b|MODE_ECB"),
        "weak or broken cryptographic primitive (MD5/SHA1/DES/ECB)",
        frozenset({"python"}),
    ),
    PatternRule(
        "crucible.weak-crypto", "CWE-327", Severity.MEDIUM,
        re.compile(r"""createHash\(\s*['"](md5|sha1)['"]"""),
        "weak hash (MD5/SHA1)",
        frozenset({"javascript", "typescript"}),
    ),
    PatternRule(
        "crucible.insecure-randomness", "CWE-330", Severity.MEDIUM,
        re.compile(
            r"(?i)(token|secret|key|password|otp|nonce|salt|session)\s*=\s*[^=\n]*"
            r"\brandom\.(random|randint|choice|randrange|getrandbits)\b"
        ),
        "insecure RNG used for a security value (use secrets/os.urandom)",
        frozenset({"python"}),
    ),
    PatternRule(
        "crucible.security-misconfig", "CWE-16", Severity.MEDIUM,
        re.compile(r"(?i)\bdebug\s*=\s*True\b"),
        "debug mode enabled",
        frozenset({"python"}),
    ),
    PatternRule(
        "crucible.insecure-transport", "CWE-295", Severity.MEDIUM,
        re.compile(r"verify\s*=\s*False|ssl\.CERT_NONE"),
        "TLS certificate verification disabled",
        frozenset({"python"}),
    ),
    PatternRule(
        "crucible.permissive-cors", "CWE-942", Severity.MEDIUM,
        re.compile(r"""(?i)(access-control-allow-origin|origins?)['"]?\s*[=:]\s*['"]\*['"]"""),
        "wildcard CORS origin",
        frozenset(),
    ),
]


def scan_patterns(source: str, language: str, *, path: str = "<memory>") -> list[Finding]:
    findings: list[Finding] = []
    seen: set[tuple[str, int]] = set()
    for lineno, line in enumerate(source.splitlines(), start=1):
        stripped = line.lstrip()
        if stripped.startswith("#") or stripped.startswith("//"):
            continue  # skip comment lines to cut noise
        for rule in RULES:
            if rule.languages and language not in rule.languages:
                continue
            m = rule.regex.search(line)
            if not m:
                continue
            if rule.value_check is not None:
                # capture group used for the value differs per rule; the secret
                # rules put the value last.
                value = m.groups()[-1] if m.groups() else ""
                if not rule.value_check(value):
                    continue
            key = (rule.rule_id, lineno)
            if key in seen:
                continue
            seen.add(key)
            f = Finding(
                rule_id=rule.rule_id,
                message=rule.message,
                severity=rule.severity,
                location=Location(path=path, start_line=lineno),
                source="crucible-pattern",
                cwe=rule.cwe,
            )
            f.evidence["pattern"] = {"kind": "config", "line": lineno}
            findings.append(f)
    return findings
