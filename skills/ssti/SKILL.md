---
name: ssti
description: Untrusted input rendered as a template, allowing template-engine expression execution.
rule_id: crucible.ssti
cwe: CWE-1336
severity: high
technique: taint
activation: ["scan for server-side template injection", "check template render safety"]
---

# Server-Side Template Injection (SSTI)

## Recon
Find template sinks whose *template string* is built from input:
`render_template_string`, `Template(...).render`, `Environment.from_string`,
Jinja/Twig/Freemarker string rendering. Distinguish from passing input as template
*data* (safe) vs as the template *source* (dangerous).

## Verify (false-positive reduction)
1. Is attacker input the template source, or just a variable rendered inside a
   fixed template? Only the former is SSTI.
2. Is a sandboxed environment used?

## Evidence
Source→sink path and the render call. Payload sketch: `{{7*7}}` → `49` confirms
evaluation.
