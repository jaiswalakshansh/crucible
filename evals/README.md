# Evals

Crucible's honesty rule: **no component ships without a measured number.** This
directory holds the benchmark harness that produces those numbers.

## Planned benchmark sets

| Set | What it measures | Target |
|-----|------------------|--------|
| OWASP Benchmark v1.2 (Java, 2,740 cases) | precision / recall / F1 of the ladder | F1 > 91% (beat standalone Semgrep's ~78%) |
| XBOW 104-challenge | PoC / exploit capability | track honestly vs. published agents |
| SEC-bench Pro | long-horizon exploit generation | report vs. the ~40% frontier ceiling |
| Curated real repos | real-world CVE yield + FP rate | ≥1 CVE; FP rate published |
| Reproducibility set | stability score across N identical runs | publish variance (a differentiator) |

## Method

Every new gate or detector is **A/B'd** against the pipeline without it. If it
does not move precision × recall, it does not merge — this is how we avoid the
documented failure mode where naive tool integration *reduced* accuracy.

*Harness implementation lands in Phase 1 alongside the first real gates.*
