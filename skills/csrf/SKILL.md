---
name: csrf
description: A state-changing endpoint that lacks anti-CSRF protection.
rule_id: crucible.csrf
cwe: CWE-352
severity: medium
technique: semantic
activation: ["scan for csrf", "check anti-csrf protection"]
---

# Cross-Site Request Forgery (CSRF)

Semantic class — requires reasoning about request-authenticity protection.

## What to look for
- State-changing handlers (POST/PUT/DELETE, or GET with side effects) that do not
  validate a CSRF token, and rely only on ambient cookies for auth.
- Frameworks with CSRF protection globally disabled, or per-view exemptions
  (`@csrf_exempt`, `csrf: false`) on sensitive actions.
- `SameSite` cookie attribute absent/`None` combined with cookie-based auth.
- CORS + credentials allowing untrusted origins (compounds CSRF).

## Verification questions for the agent
1. Does this action change state or is it purely a read?
2. Is auth cookie-based (so a cross-site request would carry it automatically)?
3. Is a CSRF token or equivalent (double-submit, SameSite=strict, origin check)
   validated for this action?

## Evidence
The handler, its side effect, and the missing protection. Report as suspected.
