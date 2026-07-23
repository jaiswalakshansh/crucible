---
name: business-logic
description: A flaw in application logic (not a generic injection) that lets an attacker abuse intended functionality.
rule_id: crucible.business-logic
cwe: CWE-840
severity: medium
technique: semantic
activation: ["scan for business logic flaws", "check logic abuse"]
---

# Business Logic Flaws (OWASP A04)

Semantic class — no signature or taint path finds these; they require
understanding intent.

## What to look for
- Price/quantity/amount taken from the client and trusted (negative quantities,
  client-set prices, discount stacking).
- Missing server-side checks on multi-step flows (skip payment, replay a coupon,
  reorder steps).
- Race conditions on limited resources (double-spend, inventory oversell) —
  check-then-act without a lock/atomic op.
- Insufficient limits (unbounded quantities, no rate limits on costly actions).
- Trusting client-computed totals/state.

## Verification questions for the agent
1. Which values that affect money/access/limits come from the client and are not
   re-validated server-side?
2. Can a step be skipped, replayed, or reordered to gain value?
3. Is there a concurrency window between a check and the action it guards?

## Evidence
The flow, the trusted-client value or missing check, and the concrete abuse.
Report as suspected with the reasoning.
