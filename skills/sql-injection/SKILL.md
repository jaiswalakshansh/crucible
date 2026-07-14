---
name: sql-injection
description: >
  Detect SQL injection: untrusted input reaching a database query without
  parameterization or safe escaping. Language-agnostic — reasons over a code
  slice and its taint path, not over syntax of a specific framework.
version: 0.1.0
cwe: CWE-89
severity: high
activation:
  - "scan for sql injection"
  - "check database query safety"
  - candidate.rule_id matches "*sql*" or "*sqli*"
---

# SQL Injection

## Recon phase
Given a code slice plus the Opengrep taint candidate (source → sink path), identify
every point where external input could reach a query-execution sink:

- **Sources**: request params/body/headers, CLI args, file/env contents, message-queue
  payloads, values read back from storage that were originally attacker-controlled.
- **Sinks**: raw query execution (`execute`, `query`, `raw`, string-built SQL, ORM
  `.raw()`/`.extra()` escape hatches).
- **Sanitizers**: parameterized/prepared statements, allow-list validation, integer
  coercion, trusted ORM query builders.

Return candidate (source, sink) pairs with the intervening data flow.

## Verification phase (false-positive reduction)
For each candidate, decide *exploitability*, not mere pattern presence:

1. Is the source genuinely attacker-controlled at runtime, or a constant/internal value?
2. Does a sanitizer neutralize the taint anywhere on the path? Parameterization ⇒ not
   exploitable — mark refuted.
3. Can the tainted value alter query *structure* (not just a bound value)?

Only forward findings where an attacker can influence query structure with no
neutralizing sanitizer on the path.

## Evidence to emit
- The concrete source→sink taint path (file:line at each hop).
- The exact sink expression and why it is unsafe.
- A minimal exploitation sketch for the PoC gate (input value + expected effect),
  e.g. `id=1 OR 1=1 --`. This feeds the sandbox PoC stage; do not claim confirmation
  here — that status is assigned only when the PoC actually fires.

## Output
Emit a `Finding` (rule_id `crucible.sql-injection`, cwe `CWE-89`, severity `high`)
per verified candidate, with `confirmation: suspected` until the ladder proves it.
