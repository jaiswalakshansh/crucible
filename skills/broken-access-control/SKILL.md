---
name: broken-access-control
description: A resource or action reachable without an ownership/authorization check (IDOR, missing authz).
rule_id: crucible.broken-access-control
cwe: CWE-639
severity: high
technique: semantic
activation: ["scan for broken access control", "check authorization / IDOR"]
---

# Broken Access Control / IDOR (OWASP A01)

This is NOT a data-flow bug — a taint engine cannot find it. It requires reasoning
about whether an authorization check exists and is correct. It is the job of a
semantic agent.

## What to look for
- A handler that fetches or mutates a resource by an id taken from the request
  (`/orders/{id}`, `?user_id=`) WITHOUT verifying the resource belongs to the
  current principal.
- Object lookups keyed by request input where the query does not scope to the
  session user (`Order.get(id)` vs `Order.get(id, owner=current_user)`).
- Admin/privileged actions with no role check.
- Access decisions made on the client, or using a request-supplied role/flag.

## Verification questions for the agent
1. Who is the authenticated principal in this handler, and how is it obtained?
2. Is the requested object scoped to that principal, or globally addressable by id?
3. Is there a decorator/middleware/guard enforcing authz for this route? Does it
   actually cover this action?
4. Could changing an id/param in the request access another user's data or action?

## Evidence
The handler, the object lookup, the principal source, and the specific missing or
insufficient check. Severity rises if the action is state-changing or exposes PII.
Confidence is inherently lower than a proven flow — report as suspected with the
reasoning, never as confirmed.
