---
name: insecure-llm-output
description: LLM/model output flowing into a dangerous sink (code/command/SQL/HTML) without validation.
rule_id: crucible.insecure-llm-output-handling
cwe: CWE-94
severity: high
technique: taint
activation: ["scan for insecure llm output", "check model output handling"]
---

# Insecure Handling of LLM Output (OWASP LLM02)

## Recon
Treat the return of a model call as untrusted: `*.messages.create`,
`*.chat.completions.create`, `*.generate_content`, chain/agent `.invoke`. Find
where that output reaches `eval`/`exec`, a shell, a SQL query, an HTML sink, a
file write, or a tool/function call (excessive agency, LLM06/08).

## Verify (false-positive reduction)
1. Is the model output used as *code/command/markup*, or only displayed/logged as
   text? Rendering as escaped text is safe.
2. Is there validation/allow-listing/schema-parsing between the model and the sink?
3. For tool-calling: are tool arguments constrained, or can the model pick an
   arbitrary command/target?

## Note
Prompt injection (untrusted input reaching the model prompt) is intentionally NOT
flagged by the detector — it is universal and unprovable statically. This skill is
about the *output* side, which is a real flow with a dangerous sink.

## Evidence
The model-output→sink path and the sink expression.
