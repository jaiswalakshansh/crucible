# Verification status

This file is the source of truth for what actually works. Every row states what a
component does, how it was checked, and what remains unverified. If a claim is not
backed by a test in this repo or a cited external source, it is marked as such.

Legend for **Verified by**:
- `unit test` — deterministic test in `tests/` exercises this code path.
- `manual run` — run by hand in this environment; command noted.
- `not run` — implemented but not executed here.
- `attributed` — a claim taken from an external source, not reproduced here.

## Components

| Component | What it does | Verified by | Not verified |
|---|---|---|---|
| `schema.Finding` / SARIF map | SARIF-2.1.0 result round-trip; carries confirmation + stability | unit test (`test_schema`) | — |
| `schema.FileRecord` / `ScanState` | idempotent merge-by-fingerprint, resumability check | unit test (`test_schema`) | behavior under a real DB backend (none exists yet) |
| `schema.sarif.build_sarif` | assembles a SARIF log | unit test (`test_schema`) | conformance against an external SARIF validator |
| `validators.ladder` | ordered gates, fail-open, stop-on-refute, confirm-only-on-PoC | unit test (`test_schema`, `test_gates`) | — |
| `PrefilterGate` | deterministic reachability annotation (soft) / refute (hard) | unit test (`test_gates`) | usefulness of the signal (no real taint source wired) |
| `AdversarialGate` | LLM disproof; verdict mapping; fail-open on error/malformed | unit test with scripted backend (`test_gates`) | **judgment quality — no model run, no benchmark** |
| `ReachabilityGate` | LLM reachability judgment; fail-open | unit test with scripted backend (`test_gates`) | **judgment quality — no model run** |
| `validators.consensus` | count runs per fingerprint, stability score, threshold | unit test (`test_consensus`) | that voting reduces real variance (not measured) |
| `PoCGate` | run a PoC, confirm on exit 0, fail-open on timeout/error | **unit test with REAL subprocess execution** (`test_poc_gate`) | model-generated PoC quality (gen path tested only with scripted spec) |
| `exploit.synthesizer` | build a PoC that calls a function with a payload; marker proves execution | **unit test, REAL execution** (`test_exploit`) | Python execution sinks only; single-callable-arg functions only |
| `exploit.prover` | prove eval/exec/os.system param flows **including cross-function chains** (drives the entry function; the sink may be several calls deep) | **unit test, REAL execution** (`test_exploit`) | cannot prove SQLi/XSS/SSRF (needs a live service); intra-file only; single-arg entry functions |
| `sandbox.LocalSubprocessExecutor` | run files+entrypoint as a subprocess, timeout | **unit test with real execution** (`test_sandbox`) | does NOT isolate untrusted code (documented); no network isolation |
| `sandbox.DockerExecutor` | run PoC in a container, `--network none` | **not run** | everything — not exercised in CI; needs docker; behavior unverified here |
| `harness.Pipeline` | candidates -> ladder -> consensus, end to end | unit test with injected source + real PoC (`test_pipeline`) | behavior with a real candidate source / live gates |
| `budget.Budget` | token/call/wall-clock caps with injectable clock | unit test (`test_budget`) | — |
| `evals.scoring` | precision/recall/F1, span-match TP/FP/FN | unit test (`test_evals`, hand-computed) | — |
| `evals.harness` | run a scan fn over labeled cases, micro-average | unit test with oracle/noisy stubs (`test_evals`) | run against a real corpus |
| `backends.FakeBackend` | scripted responses for tests | unit test (`test_gates`) | — (test-only) |
| `backends.AnthropicBackend` | real Messages API call via urllib | **not run** | everything — no key here; no integration test; live path unexercised |
| `substrate.treesitter` | parse 5 languages via tree-sitter | manual + unit (`test_taint`) | — |
| `substrate.interproc` (single-file) | inter-procedural taint: function summaries (param→sink, param→return, return-uncond) with a fixpoint; cross-function and multi-hop flows | **unit tests on real code** (`test_interproc`) + corpus; verified superset of intra | positional args only; name-based function matching |
| `substrate.interproc.analyze_project` | **cross-file** taint (Python): resolves `from x import f` / `import x` / aliases to sibling files; taint flows across modules; finding located at the sink's file | **unit tests on real code** (`test_crossfile`) | Python only; filename-stem module matching (packages match last segment); star/dynamic imports unresolved; the exploit prover is still single-file |
| `substrate.taint` (Python) | intra-procedural taint incl. call-sinks, source-kind tracking; classes: SQLi, cmd-injection, code-injection, SSRF, path-traversal, SSTI, insecure-LLM-output | **unit tests on real code** (`test_taint`) + corpus | superseded by `interproc` for scanning; still used directly by the exploit prover |
| `substrate.taint` (JS/TS) | same engine + assignment-target sinks; classes: SQLi, cmd-injection, code-injection, DOM-XSS, insecure-LLM-output | **unit tests on real code** (`test_taint`) + corpus | narrower backend packs than Python; framework-aware sources not modeled |
| `substrate.taint` assignment-sinks | detect tainted value written to a dangerous target (`el.innerHTML =`) | **unit test** (`test_taint`) | only DOM-XSS targets modeled so far |
| `substrate.taint` LLM-output source | LLM/model-call return treated as a source; flagged when it reaches a dangerous sink | **unit test** (`test_taint`) | prompt-injection (input→model) deliberately NOT modeled (would be mostly FP) |
| `substrate.taint` (Go/Java) | not implemented | n/a | **no taint adapter yet** — these languages parse but produce no findings |
| `substrate.patterns` | config/crypto point-detector (NOT taint): hardcoded secrets, weak crypto, insecure RNG, debug mode, TLS verify off, wildcard CORS | **unit tests** (`test_patterns`), precision-focused | line/regex based; no dataflow; known-token formats high-confidence, generic secret is heuristic |
| `skills` (loader + registry) | load `SKILL.md` files, parse frontmatter, match skills to findings by rule/CWE; 15 skills shipped | **unit tests** (`test_skills`) | skill *content quality* for LLMs is unmeasured (needs a model) |
| `agents.SemanticVulnAgent` | LLM agent for classes taint can't find (access control, auth, CSRF, business logic); skill-driven; findings always `suspected` | **unit tests, scripted backend** (`test_agents`) + gated live test | **detection quality unmeasured** — needs a model + benchmark |
| `agents.SeverityAgent` | CVSS-style severity assessment annotating a finding | **unit tests, scripted backend** (`test_agents`) | scoring quality unmeasured (needs a model) |
| `substrate.candidates` | walk a dir, run taint + patterns, emit findings | manual run (`crucible scan`) + corpus | — |
| `substrate.OpengrepAdapter` | shell out to Opengrep, parse SARIF | `available()` returns False here (binary absent) | scan/parse against real Opengrep output |
| `harness.Coordinator` | Phase 0 recon stage into state | manual run | superseded by `substrate.candidates` for real findings |
| `backends.AnthropicBackend` (live) | real adversarial-gate call | **gated integration test** (`tests/integration`), skipped without a key | not run here — no key present |
| CLI (`crucible`) | `version`/`info`/`scan`/`validate`/`prove` | manual run — `scan` finds real taint flows; `prove` confirms 2/3 fixture cases by real execution and leaves SQLi suspected; `validate` skips the LLM gate honestly without a key | `validate` with a real model |

## Repo-wide facts (checked)

- Test suite: **166 tests pass, 2 skipped** (both gated live-model tests) — `.venv/bin/pytest -q`.
- **Semantic-vuln agents exist for the classes taint cannot find** (broken access
  control/IDOR, auth bypass, CSRF, business logic), driven by their skills. Their
  *orchestration* is tested with a scripted backend (prompt built from the skill,
  JSON parsed, severities mapped, fail-open on error/malformed). Their *detection
  quality is unmeasured* — it needs a real model and a benchmark. `crucible
  semantic <path>` runs them when `ANTHROPIC_API_KEY` is set and otherwise says so
  and produces nothing (never faked). Agents always report `suspected`.
- **15 skills** (`skills/*/SKILL.md`) ship: one per taint class (11), plus 4 semantic
  classes (broken-access-control, auth-bypass, CSRF, business-logic) that taint
  cannot find. A tested registry loads them, validates frontmatter, and matches a
  skill to a finding by rule id or CWE. **Verifiable here:** loading, structure,
  matching, and that every detector rule has a skill. **NOT verifiable here:**
  whether a skill improves an LLM's judgment (needs a model + benchmark).
- **Config/crypto weaknesses are covered by a separate pattern detector** (they are
  not data-flow problems, so taint structurally cannot find them): hardcoded
  secrets (known token formats + a heuristic for generic ones), weak crypto
  (MD5/SHA1/DES/ECB), insecure RNG for security values, `debug=True`, disabled TLS
  verification, wildcard CORS. Precision-focused: `password = "required"`, env
  lookups, strong hashes, `secrets.token_hex`, and commented code are not flagged.
- **14 vulnerability classes** are covered by taint (up from 8): SQLi, command
  injection, code injection, SSRF, path traversal, SSTI, DOM XSS, insecure LLM
  output, plus insecure deserialization (CWE-502), XXE (611), open redirect (601),
  XPath injection (643), ReDoS (1333), and reflected XSS via mark_safe/Markup (79).
  Each has real-code unit tests; safe variants (safe_load, constant, parameterized)
  stay clean. LDAP injection is deliberately deferred (its tainted argument is not
  arg 0 — needs per-sink argument-position modeling).
- **Cross-file taint works (Python).** Input read in one file that flows into a
  helper in another file (via `from x import f`, `import x`, or an alias) is found
  and located at the sink's file; the parameterized cross-file version stays clean;
  an import of a module not in the set resolves to nothing (no crash, no false
  positive). `crucible scan <dir>` analyzes Python files together.
- **Cross-function exploit chains are proven end to end.** For a handler that passes
  a parameter to a helper (or through several helpers) that reaches an
  `eval`/`exec`/`os.system` sink, the prover drives the *entry* function with a
  payload and confirms only when the sink actually fires. Verified with real
  execution on two-hop and three-function chains; SQLi cross-function flows are
  found but left `suspected` (not provable by direct call).
- **Inter-procedural taint finds cross-function flows the intra analyzer misses.**
  Verified on real code: a handler that passes request input to a helper which hits
  a sink is now found (intra-procedural returns nothing on the same input), and
  two-hop chains are traced. Verified to be a superset of intra on the corpus (no
  existing finding is lost). Parameterized/constant cross-function calls stay clean.
- **Exploitability is proven, not asserted, for the provable subset.** For a Python
  function that passes a parameter into an `eval`/`exec`/`os.system` sink, `prove`
  synthesizes a PoC, runs it, and marks the finding `confirmed` only when
  attacker-controlled code actually executes (a marker file appears). SQLi/XSS/SSRF
  are left `suspected` because proving them needs a running service (DAST), which
  Crucible does not do. Verified with real execution in `test_exploit`.
- Lint: `ruff check src tests conftest.py` — clean.
- The tree-sitter taint analyzer is verified on **real code** (real parsing): it
  flags direct and variable-mediated source→sink flows, handles property/subscript
  sources, and correctly leaves parameterized, sanitized, and constant queries
  alone. `crucible scan` finds real flows across Python/JS/TS.
- The PoC gate and local executor are verified with **real subprocess execution**.
- No LLM API key is present in this environment; no LLM gate has been run against a
  real model (scripted backend only). The live path has a skipped integration test.
- The `opengrep` binary is absent here; taint analysis does not depend on it.
- The Docker executor is not run here; it is unverified in this repo.

## Measured numbers (with honest framing)

- **Taint analyzer on the self-authored corpus** (`evals/fixtures/taint_corpus/`,
  15 cases: 8 vulnerable, 7 safe; spanning SQLi, command injection, SSRF, path
  traversal, DOM XSS, and insecure LLM output handling, plus parameterized/
  sanitized/constant safe cases): precision 1.0, recall 1.0, F1 1.0.
  **This is not an accuracy benchmark.** The rule packs and the corpus were written
  together, so a perfect score is expected and demonstrates only that the mechanism
  works and does not regress. It says nothing about real-world code. The OWASP
  Benchmark (Java) is the real test and is still **not run** — it needs the Java
  taint adapter (not built) and a benchmark runner.

## Explicit non-results

- **No independent benchmark has been run.** The only measured number is on a
  self-authored corpus (see above), which cannot demonstrate real-world accuracy.
  The OWASP Benchmark target in `PLAN.md` is not executed anywhere in this repo.
- **Cross-file taint is Python-only and filename-based.** JS/TS remain single-file.
  Python package/dotted modules match on the last path segment; star and dynamic
  imports are not resolved. The exploit prover is still single-file (it does not yet
  prove flows whose sink is in another file).
- **Go and Java have no taint adapter.** They parse but produce no findings.
- Any accuracy or false-positive figure appearing in `PLAN.md` or
  `ai-sast-market-research.md` is either a target or a figure attributed to an
  external source. None have been reproduced by Crucible.

## External claims relied on (attributed, not reproduced)

- "Un-orchestrated coding agents show ~82–86% false positives on 11 Python apps" —
  Semgrep blog (2025). Motivates the design; not reproduced here.
- "Adversarial disagreement between two models reduces noise more than
  single-agent prompting" — Cloudflare agent-graph writeup. A hypothesis this
  project is built to test; not reproduced here.
- "Frontier models score <40% on long-horizon exploit tasks" — SEC-bench Pro.
  Basis for reporting unproven findings as `suspected`; not reproduced here.
