---
name: auth-bypass
description: Authentication that can be skipped, forged, or is missing on a protected action.
rule_id: crucible.auth-bypass
cwe: CWE-287
severity: high
technique: semantic
activation: ["scan for authentication bypass", "check auth enforcement"]
---

# Authentication Bypass (OWASP A07)

Semantic class — requires reasoning about auth flow, not a taint path.

## What to look for
- Protected routes missing an authentication guard/decorator/middleware.
- Auth decisions on trust-the-client data (a request header/cookie/param claiming
  identity or role without verification).
- Weak session/token handling: no signature/expiry check, predictable tokens,
  JWT with `alg: none` or unverified signature, secrets compared non-constant-time.
- Password checks using `==` on hashes, or missing rate limiting on login.
- Backdoor/hardcoded credentials or debug bypasses.

## Verification questions for the agent
1. Is authentication actually enforced before the sensitive action runs?
2. Is the identity/role derived from verified server state, or from client input?
3. Are tokens verified (signature + expiry + audience) before trust?

## Evidence
The route/action, the (missing or flawed) auth check, and how it can be bypassed.
Report as suspected with reasoning.
