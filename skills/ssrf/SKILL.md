---
name: ssrf
description: Untrusted input controlling the destination of a server-side HTTP request.
rule_id: crucible.ssrf
cwe: CWE-918
severity: high
technique: taint
activation: ["scan for ssrf", "check server-side request safety"]
---

# Server-Side Request Forgery (SSRF)

## Recon
Find HTTP-client sinks whose URL is influenced by input: `requests.*`,
`urllib.request.urlopen`, `httpx.*`, `fetch`, `axios`. Sources: request params,
webhooks, user-supplied URLs, metadata read back from storage.

## Verify (false-positive reduction)
1. Does attacker input control the host/scheme, or only a path under a fixed host?
2. Is there an allow-list of destinations, or scheme/host validation, before the
   request? A validated allow-list neutralizes SSRF.
3. Can the request reach internal ranges (169.254.169.254, localhost, RFC1918)?
   Reachability of internal targets raises severity.

## Evidence
Source→sink path, the URL-building expression, and whether any allow-list applies.
Note that *proving* SSRF requires a running target (dynamic testing); a static
finding stays suspected.
