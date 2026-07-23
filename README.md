# Crucible

A language-agnostic AI-assisted static analysis (AI-SAST) engine. Crucible runs
deterministic static analysis and LLM reasoning together, then puts every
candidate finding through a sequence of validation gates before reporting it.

This repository follows one rule: **claims must be verifiable.** Nothing in the
docs or code asserts a capability or a number that has not been measured in this
repo or attributed to a cited source. Where something is not yet verified, it
says so. See [STATUS.md](STATUS.md) for the per-component verification ledger.

## What it does today (verified)

- **Finds real vulnerabilities deterministically, across function boundaries.** A
  tree-sitter taint analyzer traces data from source to sink for Python,
  JavaScript, and TypeScript, with an explicit source→sink path. It is
  **inter-procedural**: a handler that passes request input to a helper which
  reaches a sink is found (and multi-hop chains are traced) — the common real-world
  shape that intra-procedural analysis misses. For Python this works **across
  files**: input read in one module that flows into a helper in another (via
  `from x import f` / `import x`) is found and located at the sink's file. Coverage
  spans three domains:
  backend (SQL injection, command injection, code injection, SSRF, path traversal,
  SSTI, insecure deserialization, XXE, open redirect, XPath injection, ReDoS),
  frontend (DOM XSS incl. `el.innerHTML =` assignment sinks, reflected XSS via
  `mark_safe`/`Markup`), and AI/LLM (insecure handling of LLM output that reaches a
  dangerous sink) — 14 classes in all. It
  correctly leaves parameterized queries, sanitized values, and constant strings
  alone. `crucible scan <path>` emits SARIF. Verified with unit tests on real code
  and a labeled corpus (see "Measured numbers" caveat below).
  Note: prompt injection (user input reaching the model) is deliberately **not**
  flagged — it is true of every LLM app and would be almost all false positives;
  static analysis cannot see whether guardrails exist.
- **Proves exploitability where it can, honestly.** For a function that passes a
  parameter into a code/command-execution sink (`eval`, `exec`, `os.system`),
  `crucible prove` synthesizes a real PoC, runs it in a sandbox, and marks the
  finding `confirmed` only when attacker-controlled code actually executes. SQL
  injection, XSS, and SSRF cannot be proven this way — they need a running service
  (dynamic testing) — so they are left `suspected`, never claimed as proven. The
  point of the tool is exploitable code, not pattern counts; this is the first
  piece that separates the two. This works **across function boundaries**: for a
  `handler → helper → os.system` chain, `prove` drives the entry function with a
  payload and confirms only if the sink actually fires several calls deep.
  Verified with real execution.
- Represents every finding in a SARIF-2.1.0-aligned model that also carries a
  `confirmation` status and a `stability` score.
- Runs candidates through a validation ladder that is **fail-open** (a gate that
  errors retains the finding) and **stops on refutation**. Only a proof-of-concept
  that executes successfully in a sandbox sets status to `confirmed`.
- Phase 1 gates: a deterministic reachability pre-filter, an LLM adversarial
  disproof gate, an LLM reachability-audit gate, and consensus voting across
  repeated runs. The gate *orchestration* is unit-tested with a scripted backend;
  the *quality* of LLM verdicts is not yet measured (no benchmark run — see below).
- Phase 2: a proof-of-concept gate that actually executes a PoC in a sandbox and
  sets a finding to `confirmed` only when the PoC exits 0. The execute-and-classify
  path is tested with **real subprocess execution** (not mocked). An end-to-end
  `Pipeline` composes candidates → validation ladder → consensus, and a `Budget`
  governor caps tokens/calls/wall-clock. A Docker executor (`--network none`)
  exists for untrusted PoCs but is not run in CI.

- **Covers classes taint cannot, via LLM agents.** Broken access control / IDOR,
  auth bypass, CSRF, and business-logic flaws are not data-flow problems, so a
  skill-driven `SemanticVulnAgent` handles them (`crucible semantic`). Findings are
  always `suspected` with the model's reasoning; agents never confirm. Their
  orchestration is tested; detection quality needs a model + benchmark (unmeasured).

## What is not yet true

- **Cross-file taint is Python-only and filename-based.** JS/TS stay single-file;
  Python package/dotted modules match on the last path segment; star/dynamic imports
  are not resolved. The exploit prover is still single-file.
- **Go and Java have no taint adapter yet.** They parse, but produce no findings.
- **No independent benchmark has been run.** The only measured number is on a
  self-authored corpus, which cannot show real-world accuracy — the rule packs and
  the corpus were written together. The OWASP Benchmark (Java) is the real test and
  is not run. Any accuracy figure in [PLAN.md](PLAN.md) is a *target*.
- The LLM gates have been exercised against a scripted backend (orchestration) and,
  optionally, a real model via a skipped, key-gated integration test. Their
  *judgment quality* is unmeasured.
- Code Property Graph and cross-repo reachability are described in
  [PLAN.md](PLAN.md) but not implemented. The Docker PoC executor exists but is not
  run in CI.

## Design premise (attributed, not asserted as fact)

Crucible is built on the hypothesis that the orchestration around a model — not
the model alone — determines usefulness for SAST, and that separating discovery
from adversarial validation reduces false positives. These are positions taken
from published writeups (Cloudflare's agent-graph post; Semgrep's 2025 coding-agent
benchmark reporting an 82–86% false-positive rate for un-orchestrated agents on 11
Python apps). They motivate the design; they are not results Crucible has
reproduced. The project's purpose is to test whether they hold.

## Two limits the design does not claim to remove

- **LLM nondeterminism** — identical input can yield different findings across
  runs. Crucible measures and reports this as a stability score rather than hiding
  it. It does not eliminate it.
- **Exploit-generation ceiling** — published benchmarks (e.g. SEC-bench Pro) report
  frontier models below ~40% on long-horizon exploit tasks. Findings without a
  successful PoC are reported as `suspected`, never as proven.

## Architecture

```
L4  autonomy      queue • per-file state • budget caps • safety constraints
L3  validation    ordered gates (deterministic + LLM), fail-open
L2  harness       coordinator + per-item agent runs
L1  skills        language-agnostic reasoning + per-vuln-class prompts
L0  substrate     tree-sitter / Opengrep / SARIF (one model per language)
```

Layers L0–L3 have partial implementations; see [STATUS.md](STATUS.md) for exactly
what exists and how it was checked. Full plan in [PLAN.md](PLAN.md); forward plan
in [ROADMAP.md](ROADMAP.md); the market research it draws on is in
[ai-sast-market-research.md](ai-sast-market-research.md).

## Scope

Local CLI first. Languages: Python, JavaScript/TypeScript, Go, Java. Pluggable,
multi-model LLM backend.

## Usage

```
crucible info              # build + capability state (e.g. whether Opengrep is present)
crucible scan <path>       # run recon, emit SARIF to stdout
crucible scan <path> -o out.sarif
```

## Development

```
python -m venv .venv && .venv/bin/pip install -e ".[dev]"
.venv/bin/pytest -q            # tests
.venv/bin/ruff check src tests # lint
```

## License

MIT © Akshansh Jaiswal
