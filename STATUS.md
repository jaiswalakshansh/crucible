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
| `sandbox.LocalSubprocessExecutor` | run files+entrypoint as a subprocess, timeout | **unit test with real execution** (`test_sandbox`) | does NOT isolate untrusted code (documented); no network isolation |
| `sandbox.DockerExecutor` | run PoC in a container, `--network none` | **not run** | everything — not exercised in CI; needs docker; behavior unverified here |
| `harness.Pipeline` | candidates -> ladder -> consensus, end to end | unit test with injected source + real PoC (`test_pipeline`) | behavior with a real candidate source / live gates |
| `budget.Budget` | token/call/wall-clock caps with injectable clock | unit test (`test_budget`) | — |
| `evals.scoring` | precision/recall/F1, span-match TP/FP/FN | unit test (`test_evals`, hand-computed) | — |
| `evals.harness` | run a scan fn over labeled cases, micro-average | unit test with oracle/noisy stubs (`test_evals`) | run against a real corpus |
| `backends.FakeBackend` | scripted responses for tests | unit test (`test_gates`) | — (test-only) |
| `backends.AnthropicBackend` | real Messages API call via urllib | **not run** | everything — no key here; no integration test; live path unexercised |
| `substrate.OpengrepAdapter` | shell out to Opengrep, parse SARIF | `available()` returns False here (binary absent) | scan/parse against real Opengrep output |
| `harness.Coordinator` | Phase 0 recon stage into state | manual run (`crucible scan`, empty findings — no Opengrep) | behavior with real candidates |
| CLI (`crucible`) | `version` / `info` / `scan` | manual run (`crucible version`, `crucible info`) | `scan` with real detectors |

## Repo-wide facts (checked)

- Test suite: **58 tests pass** (`.venv/bin/pytest -q`).
- Lint: `ruff check src tests conftest.py` — clean.
- The PoC gate and local executor are verified with **real subprocess execution**,
  not mocks: a PoC that exits 0 confirms, exit non-zero does not, a sleep times
  out. A full ladder reaches `CONFIRMED` only when a real PoC fires.
- No LLM API key is present in this environment; no LLM gate has been run against a
  real model (only against a scripted backend).
- The `opengrep` binary is absent here (`crucible info` -> `opengrep_available: false`).
- The Docker executor is not run here; it is unverified in this repo.

## Explicit non-results

- **No benchmark has been run.** The OWASP Benchmark target in `PLAN.md` is not
  executed anywhere in this repo. The only fixture present
  (`evals/fixtures/synthetic/`) is a 2-file smoke set for testing the scoring
  code path; it measures nothing about detection quality.
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
