# AI-SAST — Engineering Plan

*Goal: build the best-in-market AI-SAST — language-agnostic, best-of-breed, gap-driven. Built on the market research in [ai-sast-market-research.md](ai-sast-market-research.md).*

---

## 0. An honest north star (read this first)

The stated goal is "fill **all** gaps and never ship something with a gap." I'm going to hold that goal seriously, which means being truthful about it rather than selling it:

- **Most gaps are closeable by good engineering** — deterministic pre-filtering, adversarial validation, PoC execution, cross-repo reachability, state persistence. We *will* close these and refuse to ship a component until its gap is closed **and measured**.
- **Two gaps cannot be driven to zero with today's models, and claiming otherwise would be a lie:**
  1. **LLM nondeterminism** — identical input can yield different findings run-to-run. We can *bound* it hard (consensus voting drives variance down and makes it measurable) but not eliminate it.
  2. **Frontier PoC/exploit ceiling** — the strongest coding agents still sit below ~40% on long-horizon exploit tasks (SEC-bench Pro). We can raise our effective rate with ensembles and tooling, but some real bugs will not get an auto-PoC yet.

So the operating definition of "no gaps" for this project is: **every component ships with a measured gap-closure number and an explicit statement of residual risk. No component ships on vibes.** That is the one rule that actually produces the best tool — and it's honest.

**The core thesis** (from the research, proven both ways): *the harness is the product, not the model.* A stock coding agent with no harness runs at 82–86% false-positive rate. Everything here is a machine for driving that number toward zero **without** silently dropping true positives.

### Locked decisions (2026-07-14)

- **Operating model: Local CLI first.** You said you weren't sure — this is the right default and it's reversible, so I'm committing to it. Rationale: a CLI that scans a checked-out repo is the fastest path to a *dogfoodable* tool, lets us measure the validation ladder against benchmarks with zero infra, and carries no prompt-injection attack surface while the core is immature. The CI/GitHub-Action mode (Phase 3) and continuous service (Phase 3+) are **thin triggers layered on the exact same engine** — the harness, state, and ladder don't change, only what wakes them up. So starting local costs us nothing later.
- **Languages: Python, JavaScript/TypeScript, Go, Java** — all four are in scope. Sequenced by containerization difficulty for the PoC gate: **Python + JS/TS first** (Phase 0/1), **Go next, Java last for deep taint/PoC** (Java leads on the *benchmark* though — OWASP Benchmark is Java — so Java gets the deterministic+reasoning layers early even before its PoC sandbox is ready).
- **LLM backend: multi-model, pluggable.** Non-negotiable for us specifically, because the highest-ROI FP reducer in the research (adversarial disagreement) *requires* a second, different model. One prompt+JSON schema; strong model on validation, cheap model on recon.

---

## 1. Design principles (each traceable to evidence)

| Principle | Why (evidence) |
|---|---|
| **Separate discovery from validation; make validation adversarial** | Cloudflare Glasswing: two agents in deliberate disagreement beat any single-agent prompting. XBOW: "creative AI discovers, deterministic logic decides." |
| **Deterministic pre-filter before every LLM call** | CrewAI role paper: removing the deterministic planner dropped detection 45%. Ground the LLM in real dataflow, never raw file dumps. |
| **The terminal gate is a PoC executed in a sandbox** | Aardvark, OpenAnt (75.8% dynamic confirm), XBOW. A fake bug's PoC won't fire — the only deterministic FP filter that exists. |
| **Wire real static analysis IN, don't discard it** | IRIS/Argus (CodeQL), QASecClaw (Semgrep). But naive wiring *hurt* (CodeQL-MCP: 44%→31%) — integration is a first-class engineering problem. |
| **Consensus over single runs** | Self-consistency / SCE / MultiVer: majority-vote across independent runs is the practical answer to nondeterminism. |
| **Fail-open, never silently drop findings** | QASecClaw: if the validator errors/times out/returns bad JSON, retain the finding for human review. |
| **Fresh context per work item + hard budget caps** | Cyber-AutoAgent context-rot cliff at ~400s; Vigolium caps tokens/tool-calls/iterations/wall-clock. |
| **Per-file idempotent state** | deepsec `FileRecord`: resumability, dedup, and "run forever" fall out of file-centric state, not a global log. |
| **Rule of Two for autonomy** | Microsoft/Anthropic: never simultaneously (untrusted input + secrets + external comms). A live CI agent is an attack surface. |

---

## 2. The architecture — five layers

```
┌─────────────────────────────────────────────────────────────────┐
│ L4  AUTONOMY: queue • per-file state • budget caps • Rule-of-Two │
├─────────────────────────────────────────────────────────────────┤
│ L3  VALIDATION LADDER (the moat): 5 gates, cheapest → strongest  │
├─────────────────────────────────────────────────────────────────┤
│ L2  HARNESS: coordinator → short-lived swarm (DAG of stages)     │
├─────────────────────────────────────────────────────────────────┤
│ L1  SKILLS: language-agnostic reasoning + per-class knowledge    │
├─────────────────────────────────────────────────────────────────┤
│ L0  UNIVERSAL SUBSTRATE: one code model for every language       │
└─────────────────────────────────────────────────────────────────┘
```

### L0 — Universal substrate (this is what makes it language-agnostic)

The mistake most tools make is being language-specific (Vulnhuntr = Python/Jedi only). We invert it: **one code-property model, many language front-ends.** Nothing above L0 knows what language it's looking at.

- **Parsing:** `tree-sitter` grammars for every language → uniform AST. This is the proven language-agnostic parser layer (stack-graphs, Trailmark, deepsec-adjacent tools all build on it).
- **Name resolution & cross-file/cross-repo navigation:** **SCIP** indexes (Sourcegraph's language-agnostic protocol, successor to LSIF) + **stack-graphs** (GitHub's language-agnostic name resolution, tree-sitter-based, file-incremental). This gives us "who calls this / where does this symbol resolve" across languages and across repos.
- **Dataflow / taint substrate:** a **Code Property Graph (CPG)** model (Joern-style) as the language-neutral IR for source→sink reasoning, complemented by recent language-agnostic taint research (explicit-data-dependency tracking; YASA-style unified-AST taint). The CPG is where reachability lives.
- **Deterministic detector layer:** **Opengrep** as the primary open, fast (OCaml-5 shared-memory parallel), cross-function-taint engine across 12 languages — chosen over Semgrep because cross-function taint is open-source in Opengrep, and rules/SARIF are byte-compatible so we can run Semgrep rules unmodified too. Optional **CodeQL** adapter for deep semantic passes on its supported languages.
- **Lingua franca:** **SARIF** for every finding, in and out. Opengrep, Semgrep, CodeQL all emit SARIF; the whole pipeline speaks one schema so adding a language or a tool never touches downstream code.

> **Language-agnostic contract:** to add a language you provide (a) a tree-sitter grammar, (b) a SCIP indexer or stack-graph rules, (c) source/sink/sanitizer specs in our neutral schema. Zero changes above L0. Languages we can't yet do deep taint for still get structural + LLM-reasoning coverage (graceful degradation, never a hard "unsupported").

### L1 — Skills (encoding security knowledge)

Two-track, mirroring what works in the wild:

- **Language-agnostic reasoning skill** (OpenAnt's proven bet): one prompt asking *what does this code do / where does input originate / what security risk arises*, applied over CPG slices — portable to any language for free.
- **Per-vulnerability-class skills** (Vulnhuntr / sast-skills): a `SKILL.md` per class (injection family, XSS, SSRF, IDOR/authz, deserialization, path traversal, SSTI, secrets, crypto misuse, race/logic) with a **recon phase → verification phase** built in. 34-class coverage is the target (matching llm-sast-scanner).
- **Format:** standardized `SKILL.md` — YAML frontmatter (name/description for match), activation triggers, methodology, output template (SARIF), authorization gates. Skills are data, so security expertise is contributed by humans without touching harness code.
- **Knowledge grounding (RAG):** Argus-style retrieval from NVD/OSV/GHSA/Snyk for CVE/sink context on dependencies, scored on relevance + credibility.

### L2 — Harness (orchestration)

**Coordinator + short-lived swarm**, expressed as a **DAG of stages** (Glasswing's directed graph is the reference):

```
Recon → Slice → Hunt(fan-out) → Validate(ladder) → Trace → Dedup → Report/Patch
```

- **Coordinator** decides scope and dispatches; it never touches tools directly (planner/executor separation).
- **Hunt** fans out N *short-lived* agents, each pinned to **one attack class on one narrow CPG slice** — narrow scope + disposable context is how XBOW/Glasswing avoid the ~400s rot cliff. Each work item gets **fresh context**.
- **Backend-agnostic** agent interface (deepsec pattern): Claude / GPT / others behind one prompt+JSON schema, so we can put a strong model on validation and a cheap model on recon, and never be locked to one vendor.
- **Config-defined flows** (Seclab Taskflow pattern): stages are YAML so the pipeline is auditable and testable, not buried in code.

### L3 — The validation ladder (our competitive moat)

Every candidate climbs five gates, cheapest → most expensive. A finding is only *reported* if it survives to the gate appropriate for its severity; it is only *auto-confirmed* if it produces a firing PoC.

1. **Deterministic pre-filter** — Opengrep/CodeQL taint reachability on the CPG. No reachable source→sink path ⇒ deprioritize (don't silently drop; keep as low-confidence).
2. **Adversarial disagreement** — a *separate* agent, *different prompt, different model, no ability to emit findings*, whose only job is to **disprove** the hunter (Glasswing/OpenAnt). Must attempt multiple exploitation approaches before ruling absent.
3. **Reachability audit** — Argus 3-step: end-to-end reachability (control flow, exception handling, validation) → hop-by-hop taint (sanitizer/encoding/cast at each hop) → structured evidence. Adds the "reachable from *outside* the system?" question via cross-repo SCIP trace (Glasswing's under-served Trace stage).
4. **PoC-in-sandbox (terminal gate)** — OpenAnt's language-agnostic recipe generalized: an LLM emits a container spec (Dockerfile + test script + deps) for the target's ecosystem, we run the exploit in an **ephemeral, network-isolated sandbox**, and classify `CONFIRMED / NOT_REPRODUCED / BLOCKED / INCONCLUSIVE / ERROR`. **This is the only gate that yields "auto-confirmed, zero-FP."**
5. **Consensus** — the nondeterminism fix. Independent runs (varied seeds/models) → **majority vote**; report the finding's **stability score** (e.g. "confirmed 4/5 runs"). This converts nondeterminism from a hidden failure into a *reported, measurable* property.

**Fail-open rule everywhere:** any gate that errors/times out retains the finding for human triage — we never delete a possible true positive because a tool broke.

### L4 — Autonomy ("run forever")

- **State:** per-file `FileRecord` (candidates, findings, analysisHistory, git blob hash, verdicts). Reruns **append + merge/dedup**, never overwrite. Resumable from any interrupted stage.
- **Triggering:** commit/PR webhooks (diff-aware, changed-files-only, Anthropic's action pattern) + a **threat-model-once, scan-deltas-forever** loop (Aardvark). Batch/queue mode for whole-org sweeps (Deriv scale: 100s of repos).
- **Scale:** stateless workers over a job queue; parallelism bounded by concurrency knobs. Can burst to sandboxes for PoC.
- **Budget governors:** hard caps on tokens, tool-calls, triage iterations, wall-clock per job (Vigolium) — with graceful "stopped here, resume token X" (deepsec).
- **Security (non-negotiable):** enforce the **Rule of Two** — a scanning agent processing untrusted code does **not** simultaneously hold secrets and external network. Sandboxes are network-egress-denied by default. Treat repo content/issues as hostile (the `/proc/self/environ` prompt-injection exfiltration is the cautionary tale). Least-privilege tokens; human approval before any write/patch/PR.

---

## 3. How each identified gap is addressed — honestly

| Gap (from research) | Mechanism | Status |
|---|---|---|
| **82–86% FP on un-harnessed agents** | Full 5-gate validation ladder | ✅ **Closeable** — target <10% FP, measured on OWASP Benchmark + real repos |
| **Nondeterminism (3/6/11 findings across runs)** | Consensus voting + reported stability score | ⚠️ **Bounded, not zero** — we make it measurable and shrink variance; honest by design |
| **PoC generation weak (<40% long-horizon)** | Ensemble PoC attempts + sandbox; findings without PoC reported as "unconfirmed, needs human" | ⚠️ **Bounded** — raises effective rate; residual bugs flagged, never hidden |
| **Reachability from *outside* the system** | Cross-repo SCIP/stack-graph Trace stage | ✅ **Closeable** — a genuine differentiator few tools have |
| **Naive tool wiring regresses accuracy** | Tools as *evidence to a validator*, never as the final verdict; A/B every integration behind metrics | ✅ **Closeable** — process discipline |
| **Language lock-in** | L0 universal substrate; add-a-language contract | ✅ **Closeable** — core design goal |
| **Autonomous-agent attack surface** | Rule of Two, egress-denied sandboxes, least privilege, human-gated writes | ✅ **Closeable** — but eternal vigilance; new injection vectors will appear |

The two ⚠️ rows are the truthful boundary. We don't paper over them — we surface a stability score and a confirmation status on every finding so the user always knows what's proven vs. suspected.

---

## 4. Verification-first methodology (how we "never ship gaps")

A component is not "done" until:
1. It has a **benchmark number** on a fixed eval set (see §6), not an anecdote.
2. Its failure mode is **fail-open** and tested (inject a tool timeout, assert no true positive is dropped).
3. It's **A/B'd against the version without it** — if it doesn't move precision/recall, it doesn't ship (this is exactly how we avoid the CodeQL-MCP-style regression).
4. Its residual risk is written down.

"Never build something which has gaps" = this gate. It's the difference between the best tool and a demo.

---

## 5. Phased roadmap

**Phase 0 — Substrate & spine (weeks 1–4).** Local CLI. tree-sitter parsing, Opengrep integration, SARIF pipeline, per-file `FileRecord` state, one backend-agnostic (multi-model) agent loop. Deliverable: end-to-end **Python + JS/TS** scan producing SARIF, resumable. *Gate: reproduces Opengrep's raw findings + adds LLM triage; measured FP delta.*

**Phase 1 — Validation ladder (weeks 5–10).** Gates 1–3 (deterministic pre-filter, adversarial validator using a *second* model, reachability audit) + consensus voting. Bring **Java** in at the deterministic + reasoning layers here so we can run the OWASP Benchmark. *Gate: FP reduction ≥50% vs Phase 0 with recall loss <5% on OWASP Benchmark (QASecClaw hit 88.6% FP cut / 3.1% recall loss — that's the bar).*

**Phase 2 — PoC sandbox + language depth (weeks 11–16).** Gate 4 ephemeral sandbox PoC, sequenced **Python → JS/TS → Go** (easiest to containerize), Java PoC last. CPG dataflow for all four. *Gate: dynamic-confirmation rate reported; ≥1 real CVE found on a public repo.*

**Phase 3 — Autonomy, CI mode & scale (weeks 17–22).** Add the CI/GitHub-Action trigger and queue/service mode as thin layers on the same engine; threat-model-persist, budget governors, Rule-of-Two hardening, cross-repo Trace. *Gate: continuous operation on a multi-repo org without human babysitting; documented security posture.*

**Phase 4 — Prove "best in market" (ongoing).** Run the public benchmarks in §6 head-to-head vs Semgrep, CodeQL, Vulnhuntr, claude-code-security-review. Publish numbers. If we're not winning on precision×recall×language-coverage, we haven't earned the claim.

---

## 6. How we *prove* it's the best (not just assert it)

- **OWASP Benchmark v1.2** (2,740 Java cases) — the QASecClaw yardstick; target F1 > 91%.
- **XBOW 104-challenge benchmark** — for exploit/PoC capability.
- **SEC-bench Pro** — long-horizon security tasks; track our number honestly against the ~40% frontier ceiling.
- **Real-world CVE yield** on public repos (Argus/Vulnhuntr/Aardvark all validate this way — 0-days with CVE assignments are the ultimate proof).
- **Reproducibility metric** — our own: stability score distribution across N runs (nobody else publishes this; it's a differentiator and an honesty signal).

---

## 7. Tech-stack decisions (with rationale)

| Concern | Choice | Why |
|---|---|---|
| Parsing | tree-sitter | Only proven language-agnostic parser ecosystem |
| Deterministic SAST | **Opengrep** (+ Semgrep-rule compat, optional CodeQL) | Open cross-function taint, 12 langs, OCaml-5 parallel, SARIF |
| Code index | SCIP + stack-graphs | Language-agnostic, cross-repo, file-incremental |
| Dataflow IR | CPG (Joern-style) | Language-neutral source→sink substrate |
| Finding schema | SARIF everywhere | One schema; adding tools/langs never touches downstream |
| Agent backends | pluggable (Claude/GPT/…) behind one schema | No vendor lock; right model per stage |
| Tool wiring | **MCP** for SAST/index tools | Standard, but tools are evidence-to-validator only |
| State | per-file records + job queue | Resumable, idempotent, "run forever" |
| Sandbox | ephemeral containers, egress-denied | PoC gate + Rule-of-Two safety |

---

## 8. Open problems we are NOT pretending to have solved

1. **Zero nondeterminism** — impossible today; we bound + report it.
2. **100% auto-PoC** — frontier ceiling is real; unconfirmed findings are labeled, not hidden.
3. **Prompt-injection immunity** — moving target; Rule of Two reduces blast radius, doesn't grant immunity.
4. **Deep taint for every language on day one** — new languages start at structural + reasoning coverage and deepen over time (graceful, disclosed).

Naming these *is* the "always speak truth" requirement. A tool that hides them is worse, not better.

---

## 9. Immediate next steps

Scope is locked (§0.1). Phase 0 is unblocked. Concrete first tasks, in order:

1. **Repo skeleton + `git init`** (this dir isn't a git repo yet) — monorepo with `core/` (harness, state), `substrate/` (tree-sitter, Opengrep, SARIF adapters), `skills/` (`SKILL.md` files), `validators/` (the 5 gates), `backends/` (pluggable LLM interface), `evals/` (benchmark harness).
2. **SARIF finding schema + `FileRecord` state model** — the two data contracts everything else depends on.
3. **Opengrep adapter** → raw SARIF findings for Python + JS/TS (the deterministic floor to beat).
4. **Backend-agnostic agent interface** (one prompt+JSON schema, Claude + one other model wired) so adversarial validation is possible from day one.
5. **Eval harness** wired to OWASP Benchmark + a couple of public repos, so every subsequent component is measured, not guessed (the §4 gate).

Tell me to start and I'll scaffold Phase 0 (steps 1–2 first, then 3–5).
