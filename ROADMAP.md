# Roadmap

This is a forward plan, not a status report. For what actually works today, read
[STATUS.md](STATUS.md) — it is the source of truth. Nothing here is claimed as
done. Items are ordered by leverage: how much each one moves real-world true
positives, false positives, and coverage.

A distinction this roadmap keeps honest throughout: **not every vulnerability class
is a data-flow problem.** Injection classes fit the source→sink taint engine.
Access-control, authentication, and business-logic flaws do not — they need
semantic (LLM) reasoning or dynamic testing. Each item below says which technique
it actually requires, so we never pretend the taint engine covers something it
structurally cannot.

---

## Where we are (the constraints this roadmap attacks)

Verified today: intra-procedural taint for Python/JS/TS; SQLi, command injection,
and code injection; a validation ladder whose LLM gates are orchestration-tested
but not quality-measured; a PoC gate verified with real execution.

The three gaps that matter most:

1. **Recall is capped by intra-procedural analysis.** Any flow that crosses a
   function or file boundary is missed. This is the single largest gap.
2. **Coverage is narrow.** Three sink families, three languages, call-sinks only
   (no assignment sinks like `el.innerHTML = x`), no framework-aware sources.
3. **No independent measurement.** The only number is on a self-authored corpus,
   which proves the mechanism works but nothing about real code.

---

## R1 — Inter-procedural data flow (the biggest recall unlock)

**Problem:** taint stops at function boundaries, so real vulnerabilities that pass
through a helper, a class method, or another file are false negatives.

**Plan:**
- Build a **call graph** and a lightweight **Code Property Graph** over the
  tree-sitter ASTs, using SCIP / stack-graph name resolution for cross-file symbol
  binding (already the intended L0 substrate in [PLAN.md](PLAN.md)).
- Add **function summaries**: for each function, compute whether a parameter taints
  a return value or reaches a sink (a taint-through summary), then propagate across
  call sites. This is the standard way to get inter-procedural reach without
  re-analyzing callees inline every time.
- Track taint through **returns, fields, containers, and simple aliasing**.

**Technique:** static data-flow. **Honest limit:** full precision here is a
research-grade problem; we will ship bounded summaries and *measure* the recall
gain rather than claim completeness. Path explosion and dynamic dispatch will
remain sources of both FN and FP; those will be documented.

**Done when:** a labeled multi-function/multi-file corpus shows a measured recall
increase over the intra-procedural baseline, with precision tracked separately.

---

## R2 — Coverage: a source→sink→sanitizer taxonomy across all three domains

Coverage expansion is mostly **data** (rule packs) plus a few **engine features**.
The engine features gate several classes, so they are listed explicitly.

### Engine features required (prerequisites for the classes below)
- **Assignment-target sinks** — e.g. `element.innerHTML = tainted`, `x.dangerouslySetInnerHTML`.
  Today only call-sinks are detected. (Needed for DOM XSS.)
- **Framework-aware sources** — route-handler parameters as sources (Flask/Django
  request, Express `req`, FastAPI/Spring annotated params). Biggest single recall
  lever for backend web code; requires per-framework models.
- **Taint through data structures** (dicts/lists/objects) and format strings.
- **Return-value and field taint** (shared with R1).

### Backend (taint-flow-amenable — fits the engine)
| Class | CWE | Notes |
|---|---|---|
| SQL injection | CWE-89 | shipped |
| Command injection | CWE-78 | shipped |
| Code injection / eval | CWE-94/95 | shipped |
| Path traversal | CWE-22 | file-open sinks; `../` sanitizers |
| SSRF | CWE-918 | HTTP-client sinks; allowlist sanitizers |
| Server-side template injection | CWE-1336 | template-render sinks |
| XXE | CWE-611 | XML-parser sinks with external-entity config |
| NoSQL / LDAP / XPath injection | CWE-943/90/643 | query-builder sinks |
| Insecure deserialization | CWE-502 | `pickle`/`yaml.load`/`ObjectInputStream` sinks (partial — often no taint needed) |
| Open redirect | CWE-601 | redirect sinks |
| Log / header injection | CWE-117/113 | logging / response-header sinks |
| ReDoS | CWE-1333 | tainted regex source — partial |

### Frontend (mostly taint-flow-amenable; needs assignment-sink support)
| Class | CWE | Notes |
|---|---|---|
| DOM XSS | CWE-79 | sources: `location`, `document.URL`, `postMessage`; sinks: `innerHTML=`, `document.write`, `eval` |
| Reflected/stored XSS | CWE-79 | server-side: tainted → HTML template sink |
| `dangerouslySetInnerHTML` / `v-html` | CWE-79 | React/Vue assignment sinks |
| Client-side open redirect | CWE-601 | `location =` sink |
| Prototype pollution | CWE-1321 | tainted key into recursive merge sink |
| postMessage origin misuse | CWE-346 | missing origin check (partly config) |
| Sensitive data in `localStorage` | CWE-922 | storage sinks |

### AI / LLM (OWASP LLM Top 10 — several fit the taint engine)
| Class | LLM Top 10 | Technique |
|---|---|---|
| Prompt injection | LLM01 | taint: untrusted input → LLM prompt without isolation |
| Insecure output handling | LLM02 | taint: LLM output → dangerous sink (eval/exec/SQL/HTML/shell) — high value, fits engine directly |
| Excessive agency / unsafe tool use | LLM06/08 | taint: LLM output → tool/shell/file/MCP call |
| SSRF via LLM / RAG injection | LLM01/06 | taint: retrieved/untrusted content → request or prompt |
| Sensitive-info disclosure | LLM06 | taint: secret/PII source → prompt or external send |
| Insecure plugin/function-calling wiring | LLM07 | pattern + taint on tool arguments |

**"Insecure output handling" and "excessive agency" are the highest-value AI items**
because they are literally source→sink flows (LLM output is the source, a dangerous
API is the sink) and the engine already models that shape.

### Config / pattern classes (NOT flow — single-point matches)
Hardcoded secrets (CWE-798), weak crypto (CWE-327), missing security headers,
insecure cookie flags, permissive CORS, TLS misconfig. These need a **pattern
matcher**, not taint. Worth adding as a separate lightweight detector so coverage
is honest about them rather than silently missing them.

### Semantic / dynamic classes (NOT static flow — need LLM or DAST)
Broken access control / IDOR (CWE-639), auth bypass, CSRF, mass assignment,
business-logic flaws, race conditions. **The taint engine cannot find these.** They
are the job of the LLM reachability/adversarial gates and, eventually, dynamic
testing. Listing them here is the honest boundary: we will route them to the right
technique, not fake taint coverage for them.

---

## R3 — Coverage measurement ("ensure coverage: source, sink, flow")

To *know* we are not missing things, coverage must be measured, not assumed.

**Plan:** a `crucible coverage <path>` report that states, per language and per
sink family: how many files were parsed vs skipped (unsupported language, parse
error), how many sink call-sites were seen, how many had a source→sink path
evaluated, and which sink families have no rule pack. Surface the gaps loudly.

**Why:** a scanner that silently skips half a codebase reads as "clean" when it is
not. This report turns coverage into a number the user can see — directly serving
"don't miss things." It is also a differentiator; most tools do not expose it.

---

## R4 — Evaluation framework (adopting the Ethiack methodology)

Source: Ethiack, *Evaluating Pentesting Agents, Part 1*
(https://ethiack.com/info-hub/research/evaluating-pentesting-agents-part-1). These
are their principles, applied here; we have not reproduced their results.

**Plan:**
- **Real deployable targets with expert-annotated ground truth**, not CTF flags or
  synthetic snippets. Start with the OWASP Benchmark (Java) once the Java taint
  adapter (R5) exists, then add a small set of real open-source apps with curated
  vulnerability lists.
- **LLM-as-judge + bipartite matching**: match agent findings to ground-truth by
  semantic correspondence, then resolve many-to-many into one-to-one with the
  Hungarian algorithm so duplicates cannot inflate the score.
- **Report precision and recall separately**, plus a **CVSS-based severity score**
  and **CWE coverage** — not F1 alone. Ethiack's point: "low precision becomes
  operationally unusable despite competitive F1 scores."
- **Treat unmatched findings as candidate discoveries**, not automatic false
  positives; queue them for review. Ground-truth is *living*.
- **Robustness via repeated runs**, reporting the existing stability score
  distribution — the honest handle on non-determinism.

**Done when:** STATUS.md carries a real precision/recall/severity/CWE table on an
independent target, with the methodology and its limits written down. This is the
first point where Crucible's accuracy is measured rather than asserted.

---

## R5 — Language coverage: Go and Java taint adapters

Go and Java already parse; they need taint adapters (the neutral vocabulary is
defined, so this is adapter + rule-pack work). Java is the priority because the
OWASP Benchmark is Java and R4 depends on it. **Technique:** static flow. **Done
when:** each language passes an equivalent labeled corpus and is enabled for
`deep_taint` only after that.

---

## R6 — Validation ladder maturation (turning candidates into confirmed findings)

The gates exist but are not yet effective end to end:
- **Per-class PoC templates** so the PoC gate can actually generate a firing
  exploit per sink family (SQLi payload, SSRF callback, XSS reflection probe),
  run in the Docker `--network none` sandbox.
- **Reachability gate grounded in the R1 call graph**, not just the LLM's guess.
- **A real backend run** behind a key, measured against R4 — so we learn whether
  the adversarial gate actually improves precision, and by how much, rather than
  assuming it.

**Honest note:** the frontier PoC-generation ceiling (published <40% on
long-horizon exploits) still applies; unconfirmed findings stay `suspected`.

---

## Suggested sequence

1. **R2 engine features + backend/AI taint packs** — most coverage per unit effort;
   "insecure output handling" and DOM XSS are high-value and mostly rule-pack work
   once assignment-sinks land.
2. **R3 coverage report** — cheap, and it makes every later gap visible.
3. **R1 inter-procedural** — the big recall unlock; larger and needs care.
4. **R5 Java adapter** → **R4 evaluation on OWASP** — the first real accuracy number.
5. **R6 ladder maturation** with a live backend, measured against R4.

Each item ships only with a measured result and a written residual risk, per the
repo's rule. Coverage claims will be backed by the R3 report; accuracy claims by
the R4 harness. Until then they remain plans.
