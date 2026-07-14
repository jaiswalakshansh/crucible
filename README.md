# Crucible

A language-agnostic AI-assisted static analysis (AI-SAST) engine. Crucible runs
deterministic static analysis and LLM reasoning together, then puts every
candidate finding through a sequence of validation gates before reporting it.

This repository follows one rule: **claims must be verifiable.** Nothing in the
docs or code asserts a capability or a number that has not been measured in this
repo or attributed to a cited source. Where something is not yet verified, it
says so. See [STATUS.md](STATUS.md) for the per-component verification ledger.

## What it does today (verified)

- Parses a target directory, selects files in a supported language, and runs the
  Opengrep deterministic scanner when its binary is present (degrades to no-op
  recon when it is absent).
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

## What is not yet true

- **No benchmark has been run.** The plan targets the OWASP Benchmark; the scoring
  harness exists and its metric math is tested, but it has not been executed
  against OWASP or any real corpus in this repo. Any accuracy figure quoted in
  [PLAN.md](PLAN.md) is a *target*, not a result.
- The LLM gates have been exercised only against a deterministic fake backend to
  test orchestration. A real backend (Anthropic) is implemented but is not run in
  CI and requires an API key.
- Deep taint, Code Property Graph, cross-repo reachability, and the PoC sandbox
  are described in [PLAN.md](PLAN.md) but not implemented.

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
what exists and how it was checked. Full plan in [PLAN.md](PLAN.md); the market
research it draws on is in [ai-sast-market-research.md](ai-sast-market-research.md).

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
