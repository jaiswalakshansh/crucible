# Crucible

**A language-agnostic, best-of-breed AI-SAST engine — where findings are forged and tested under fire until proven.**

Crucible is an AI static application security testing tool built on a hard rule: **no finding reaches you on a guess.** A stock coding agent pointed at code runs at an 82–86% false-positive rate. Crucible wraps the model in a harness whose entire job is to drive that number toward zero — *without* silently dropping real vulnerabilities — and to be honest about the two limits that today's models genuinely cannot cross.

> The harness is the product, not the model.

## What makes it different

- **Language-agnostic by construction.** One universal code model (tree-sitter + SCIP/stack-graph indexing + a Code Property Graph + Opengrep), all speaking SARIF. Everything above that layer is language-blind. Adding a language never touches the engine.
- **A 5-gate validation ladder** — every candidate climbs from cheapest to strongest: deterministic taint pre-filter → an adversarial validator (a *different model* whose only job is to disprove the finding) → reachability audit → **proof-of-concept executed in a sandbox** → consensus vote across runs.
- **Proof over claims.** The terminal gate is a working PoC that actually fires in an isolated container. A fake bug's exploit won't run — the only deterministic false-positive filter that exists.
- **Honest about its limits.** LLM nondeterminism and the frontier exploit-generation ceiling cannot be driven to zero. Crucible *bounds and reports* them — every finding carries a **stability score** and a **confirmation status** (proven vs. suspected) rather than pretending certainty.
- **Fail-open, never silent.** If any validator errors or times out, the finding is retained for human review. Crucible never deletes a possible true positive because a tool broke.

## Status

Early development. See **[PLAN.md](PLAN.md)** for the full engineering plan and **[ai-sast-market-research.md](ai-sast-market-research.md)** for the market research this is built on.

**Locked scope:** local CLI first · Python, JS/TS, Go, Java · multi-model pluggable backend.

## Architecture at a glance

```
L4  AUTONOMY      queue • per-file state • budget caps • Rule-of-Two safety
L3  VALIDATION    5 gates, cheapest → strongest (the moat)
L2  HARNESS       coordinator → short-lived agent swarm (a DAG of stages)
L1  SKILLS        language-agnostic reasoning + per-vuln-class knowledge
L0  SUBSTRATE     one code model for every language (tree-sitter/CPG/Opengrep/SARIF)
```

## License

MIT © Akshansh Jaiswal
