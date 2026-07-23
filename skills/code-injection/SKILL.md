---
name: code-injection
description: Untrusted input reaching a dynamic code-evaluation sink (eval/exec).
rule_id: crucible.code-injection
cwe: CWE-95
severity: high
technique: taint
activation: ["scan for code injection", "check eval/exec safety"]
---

# Code Injection

## Recon
Find dynamic-evaluation sinks fed by input: `eval`, `exec`, `compile`,
`Function()` (JS), template `eval`. Sources: request data, config, deserialized
values.

## Verify (false-positive reduction)
1. Is the evaluated string attacker-controlled, or a constant/whitelisted expression?
2. Is a restricted evaluator used (`ast.literal_eval`, a sandbox)? `literal_eval`
   is safe — it is not this bug.

## Evidence
Source→sink path. This class is often directly *provable*: if the tainted parameter
is a function argument, `crucible prove` calls the function with a payload and
confirms real code execution.
