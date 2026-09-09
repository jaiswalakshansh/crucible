# Roadmap v2 — Precision-First Validation & the Feedback Loop

This supersedes roadmap v1 (whose R1 inter-procedural, R2 coverage, and R4 real-app
measurement are shipped — see git history and [STATUS.md](STATUS.md)). It is a
forward plan, not a status report; [STATUS.md](STATUS.md) remains the only source
of truth for what actually works. Nothing here is claimed as done.

---

## 0. The reframe

The goal is now stated sharply: **a finding Crucible *surfaces* must be true.** We
optimize the precision of the *reported* set toward ~100%, in the sense of
exploitability — not the precision of every candidate the detectors produce.

This is deliberately the XBOW / Cloudflare-Glasswing model from the original market
research: *creative discovery is cheap; deterministic or dynamic proof decides what
is real; only what survives proof is reported.* A false alarm costs user trust
permanently; an unproven-but-plausible candidate is not a "finding," it is a
*queued lead*. The two must never be mixed in the default output.

Where we are (honest): the detectors have good recall on real code (DSVW 12/12,
recall 1.0) and low false positives on clean code (requests 0, flask 3, all
defensible). But almost everything is reported as `suspected`; only a narrow class
(param → `eval`/`exec`/`os.system`) is ever `confirmed` by execution. To make
"every reported finding is true" real, validation — not detection — is now the
main engineering front.

---

## 1. Confidence-tiered reporting (the operating model)

Every finding lands in one of three tiers. The tier, not the detector, decides
whether it is surfaced.

| Tier | Meaning | Surfaced by default? | Precision target |
|---|---|---|---|
| **CONFIRMED** | Exploitability *proven* — a PoC fired in a sandbox, or a DAST payload was observed to trigger the sink | Yes | ~100% |
| **VALIDATED** | Not executed, but passed the full static + adversarial ladder with high confidence (reachable path + independent adversarial agreement + stable across runs); or a deterministic fact (a real hardcoded key, TLS off) | Yes, clearly labeled "not executed" | high, measured |
| **SUSPECTED** | A candidate only — detector fired, validation incomplete or ambiguous | **No** — goes to a triage queue (`--all`) | n/a (this is where recall lives) |

**Code change:** add a `VALIDATED` status alongside the existing
`ConfirmationStatus`, attach a numeric `confidence` to every finding, and make the
reporter/CLI default to `CONFIRMED + VALIDATED` with `SUSPECTED` behind a flag.
This is the single most important structural change and it is fully verifiable
without any external dependency.

**Why this is honest:** we never claim 100% precision for static suspicion. We
claim it as a *target for the CONFIRMED tier*, approached by proof. VALIDATED is
labeled as reasoned-not-executed. SUSPECTED is not shown, so it cannot be a false
alarm.

---

## 2. What "proven" means per class (the road to the CONFIRMED tier)

Precision-first means each class needs a defined proof mechanism, or it caps at
VALIDATED — stated honestly, never faked.

| Class | Proof mechanism → CONFIRMED | Ceiling if unproven |
|---|---|---|
| Code / command injection (param-reachable) | PoC executes attacker code in sandbox — **shipped** | — |
| SQLi, reflected/DOM XSS, SSRF, SSTI, open redirect, path traversal | **DAST**: run the app, send a payload to the entry route, observe the effect (DB error/boolean-diff, script reflection, out-of-band callback, file read) | VALIDATED |
| Insecure deserialization, XXE | gadget/entity PoC in sandbox | VALIDATED |
| Hardcoded secret, weak crypto, TLS off, permissive CORS | deterministic fact — verified by format/entropy/flag | **VALIDATED** (facts, not exploits) |
| Access control / IDOR, auth bypass, CSRF, business logic | require app semantics + often human judgment | **VALIDATED at best** — never auto-confirmed |

The honest boundary is explicit: web-injection classes reach CONFIRMED **only** via
DAST (§4); semantic classes never auto-confirm.

---

## 3. Coverage, in depth (raises recall *and* the quality of validation inputs)

Better detection precision directly raises how much can be validated, so this is
not separate from the precision goal.

- **P1 · Per-sink argument positions** — today only argument 0 is checked, which is
  why LDAP injection (tainted *filter* arg) was deferred. Model the dangerous
  argument index/keyword per sink. Unlocks LDAP, `subprocess([...])` list forms,
  ORM helpers, `cursor.execute(sql, params)` nuances. Small, deterministic, testable.
- **Sanitizer / validator models per class** — precise "this path is neutralized"
  knowledge (parameterized queries, `shlex.quote`, `os.path.realpath` + prefix
  check, output encoders, allow-lists). Fewer false paths → higher confidence →
  more findings legitimately reach VALIDATED.
- **Framework source models as data packs** — Django/FastAPI/Flask/Express/Rails
  request objects, route-parameter binding, ORM entry points. Recall on real apps.
- **Container / field-sensitive dataflow** — precise taint through dict/list
  elements and object fields (currently coarse), reducing both FN and FP.
- **Languages** — Go and Java taint adapters (grammar already parses); Java also
  unblocks the OWASP Benchmark. Gated on being measured against real Go/Java apps.
- **Cross-file / cross-repo** — cross-file is shipped for Python; extend the
  exploit prover across files, and add cross-repo reachability ("can external input
  reach this at all?").

---

## 4. Dynamic validation (DAST) — the precision engine for web classes

This is what makes SQLi/XSS/SSRF reach CONFIRMED, and it is the biggest new
capability. Architecture:

1. **Target runner** — bring the app up in a container (or attach to a running
   instance) from a small per-app descriptor (how to start it, base URL, routes).
2. **Entry mapping** — connect a static taint finding (source = an HTTP parameter
   on a known route) to a concrete request that reaches it.
3. **Payload library per class** — SQLi (boolean/time/error), XSS (reflection
   probe), SSRF (out-of-band callback), path traversal (`../` marker), etc.
4. **Oracle** — observe the effect deterministically: DB error / boolean-diff,
   reflected marker in the response, a callback hit on our collaborator, a sentinel
   file read. A fired oracle → CONFIRMED with the request/response transcript.
5. **Safety** — non-destructive payloads only, network-isolated target, budget caps
   (the sandbox and Rule-of-Two constraints already in the repo apply).

Honest scoping: DAST needs a runnable target, so it starts with apps that ship a
run descriptor (our fixtures, DSVW, pygoat) and generalizes outward. It is phased
and large; it is *the* path to trustworthy web-vuln findings.

---

## 5. The feedback loop (learn, and become a better harness)

The harness must improve itself from measured outcomes. This formalizes — as code
and CI — the triage-and-tune cycle done by hand in the last several PRs.

```
   detect → validate → tier → report
                ↑                     ↓
            tune rules  ←  triage  ←  measure (precision/recall per tier, per rule)
            + regress                     ↑
                └─────── growing labeled corpus (real apps) ──────┘
```

Pieces to build:

- **Living eval corpus** — versioned manifests for real apps: vulnerable
  (DSVW, pygoat, django.nV) for recall, clean (requests, flask, larger) for the
  false-positive rate. Ground truth maintained as apps change.
- **Metrics over time** — per-rule and per-tier precision/recall/F1, recorded each
  run; a trend, not a one-off. Ethiack's lesson baked in: report precision and
  recall separately, plus severity and CWE coverage.
- **Regression gate** — CI fails if CONFIRMED-tier precision drops or a known TP
  regresses. Every real false positive found becomes a committed fixture; every
  missed true positive (from unmatched-finding review) becomes a new pattern/source.
  *This is the concrete "no finding ships without a measured number" rule turned
  into automation.*
- **Triage queue** — SUSPECTED findings land here with their evidence; a human (or,
  gated, an LLM) labels them; labels flow back into rules, sanitizers, and
  suppressions.
- **LLM-in-the-loop learning (gated on a key)** — accumulate adversarial-validator
  verdicts and human triage labels as few-shot exemplars / learned suppressions,
  and *measure* whether they raise precision before trusting them. Never assumed.
- **Continuous operation** — scheduled re-scans of the corpus and of watched repos
  (the autonomy layer already sketched): detect drift, catch regressions, keep the
  numbers honest over time.

---

## 6. Harness architecture rethink (the code)

Refactor toward explicit, contract-bound stages so validators and the feedback loop
are first-class rather than bolted on:

```
Detectors            Candidates      Validation ladder                 Confidence     Reporter          Feedback
(taint / pattern  →  (Finding    →   deterministic reachability   →    tier +      →  surface CONFIRMED  →  eval corpus →
 / semantic agent)    stream)        → adversarial LLM                  score          + VALIDATED;          metrics →
                                     → PoC / DAST                                      queue SUSPECTED      triage → tune → regress
                                     → consensus
```

- **Validators are plugins** behind one interface (deterministic, LLM, PoC, DAST),
  each returning a verdict + confidence delta; the ladder composes them and is
  fail-open (never drops a candidate on tool error — it demotes it).
- **Confidence scoring** is its own module: a transparent function of which gates
  passed, agreement, reachability strength, and stability — auditable, not a magic
  number.
- **Reporter is tier-aware**; SARIF carries the tier + confidence + full evidence
  chain so downstream tools and humans see *why* something is CONFIRMED.
- **Rule packs, framework models, payload libraries, and app descriptors are data**,
  not code — so coverage grows by adding data and the feedback loop can tune them.

---

## 7. Phased plan (each phase ships measured, honest, regression-gated)

- **P1 — Precision spine (all verifiable now, no external deps):**
  per-sink argument positions; the `VALIDATED` tier + confidence scoring +
  tier-aware reporter/CLI; formalize the feedback loop (corpus + metrics + CI
  regression gate); widen real-app measurement (django.nV + a large clean app).
- **P2 — Precision depth:** sanitizer/validator models; framework source packs;
  container/field-sensitive dataflow. Measured precision/recall deltas per change.
- **P3 — DAST engine:** target runner + oracle + payload libraries; bring SQLi/XSS/
  SSRF to CONFIRMED on apps with a run descriptor.
- **P4 — Learning loop (gated on a model key):** LLM-in-the-loop validation and
  learned suppressions, adopted only if measured to raise precision; live gated runs.
- **P5 — Breadth:** Go/Java taint adapters; OWASP Benchmark (needs the Java adapter);
  cross-repo reachability; cross-file exploit proving.

---

## 8. Honest boundaries (the rule, restated)

- **~100% precision is a target for the CONFIRMED tier only**, reached by execution
  or DAST — never claimed for static suspicion, never for the VALIDATED tier, never
  for semantic classes.
- **SUSPECTED is not surfaced by default** — that is how we keep reported precision
  high without throwing away recall.
- **External dependencies stay gated and labeled:** DAST needs runnable targets;
  the learning loop and semantic-agent quality need a model key + benchmark; the
  OWASP Benchmark needs a Java adapter. None are faked; each ships only when it can
  be measured.
