---
name: open-redirect
description: Untrusted input controlling a redirect target, enabling phishing / token leakage.
rule_id: crucible.open-redirect
cwe: CWE-601
severity: medium
technique: taint
activation: ["scan for open redirect", "check redirect target safety"]
---

# Open Redirect

## Recon
Find redirect sinks whose target is input-controlled: `redirect(...)`,
`HttpResponseRedirect`, `res.redirect`, assignment to `location.href`. Sources: a
`next`/`return_to`/`url` parameter.

## Verify (false-positive reduction)
1. Is the target attacker-controlled (full URL/host), or restricted to a relative
   path or an allow-list of internal destinations?
2. Relative-only redirects (leading `/`, no `//`) or allow-listed hosts are safe.

## Evidence
Source→sink path and the redirect call. Payload sketch: `//evil.example`.
