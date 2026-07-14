"""SARIF 2.1.0 report assembly — Crucible's lingua franca on the way out.

Everything downstream (CI annotations, dashboards, other tools) consumes SARIF,
so the whole engine speaks one schema and adding a language or detector never
touches this layer.
"""

from __future__ import annotations

from typing import Any

from crucible import __version__
from crucible.schema.finding import Finding

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"


def build_sarif(findings: list[Finding], *, tool_name: str = "Crucible") -> dict[str, Any]:
    """Assemble a SARIF log from findings. One run, one tool."""
    rules_index: dict[str, int] = {}
    rules: list[dict[str, Any]] = []
    results: list[dict[str, Any]] = []

    for f in findings:
        if f.rule_id not in rules_index:
            rules_index[f.rule_id] = len(rules)
            rule: dict[str, Any] = {"id": f.rule_id, "name": f.rule_id}
            if f.cwe:
                rule["properties"] = {"cwe": f.cwe}
            rules.append(rule)
        result = f.to_sarif_result()
        result["ruleIndex"] = rules_index[f.rule_id]
        results.append(result)

    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": tool_name,
                        "version": __version__,
                        "informationUri": "https://github.com/jaiswalakshansh/crucible",
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }
