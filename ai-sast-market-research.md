# How Open-Source Security Agents Build AI-SAST — Market Research

*Compiled July 2026. Focus: harness/orchestration, skills & prompt structure, finding verification & validators, SAST/MCP tool wiring (Semgrep, Opengrep, CodeQL, tree-sitter), and autonomous "run-forever" design. Every architecture claim below is drawn from a primary or vendor source, cited inline.*

---

## TL;DR — what the field has converged on

If you strip away the branding, the serious open-source and open-core AI-SAST systems have converged on the **same five-part recipe**:

1. **The harness is the product, not the model.** The competitive edge is the orchestration graph — how you fan out narrow agents, constrain their tools, and make them disagree — not which LLM you call. Cloudflare and Jamie Lord say this explicitly, and Semgrep's benchmark proves the negative case: a *stock* coding agent with no harness runs at an **82–86% false-positive rate**.
2. **Split discovery from validation, and make validation adversarial.** Nearly every credible system uses a *different agent, different prompt, sometimes a different model*, whose only job is to disprove the finding. "Creative AI discovers. Deterministic logic decides what's real." (XBOW)
3. **The strongest validator is a working PoC executed in a sandbox.** Aardvark, OpenAnt, XBOW and Cloudflare Glasswing all gate findings on "did the exploit actually fire in a container?" This is the deterministic verifier that filters hallucinations.
4. **Classic static analysis is wired *in*, not thrown away.** The winning pattern is neurosymbolic: LLM for reasoning/reachability + Semgrep/Opengrep/CodeQL/tree-sitter for ground-truth data flow, usually exposed to the agent as **MCP tools** or as pipeline steps.
5. **"Run forever" = per-file idempotent state + resumable queues + budget caps.** Continuous operation is a state-management problem (threat model persistence, DB-backed resumable taskflows, per-file records) plus hard caps on tokens/tool-calls/wall-clock to stop context rot.

The single unsolved problem everyone is fighting is **false positives + nondeterminism**: Semgrep found that three identical runs of the same agent on the same code produced 3, then 6, then 11 findings. Every architecture below is, at heart, a machine for beating that number down.

---

## The landscape at a glance

| Project | Origin | Harness pattern | Validation mechanism | SAST/tool wiring | Autonomy model |
|---|---|---|---|---|---|
| **Vulnhuntr** | Protect AI (OSS) | Iterative single-agent call-chain tracer | Confidence score (7/8+ tiers) + PoC | Jedi parser (Python only) | On-demand CLI |
| **XBOW** | XBOW (commercial) | Coordinator + thousands of short-lived agents | Deterministic exploit validation, "zero FP" | None (pure agentic) | Long-running autonomous |
| **Aardvark** | OpenAI (beta) | 4-stage pipeline (threat-model→scan→validate→patch) | Sandbox exploit attempt + Codex patch | No traditional SAST | Continuous commit monitoring |
| **claude-code-security-review** | Anthropic (OSS) | Multi-stage Python pipeline | LLM FP-filter stage (tunable) | Deliberately none | Diff-aware GitHub Action |
| **deepsec** | Vercel Labs (OSS) | File-centric append-only pipeline | `revalidate` agent (−50% FP) | Regex matchers + plugins | Resumable, 1000+ sandboxes |
| **Semgrep Workflows / MCP** | Semgrep (open-core) | Programmable Python-SDK pipeline | LLM exploitability classification step | *Is* the SAST engine; MCP server | CI + Assistant |
| **Opengrep** | 10-vendor fork (OSS) | Deterministic engine (not an agent) | Taint analysis, test cases | Engine other agents wrap | Library/CLI |
| **IRIS** | Academic (OSS) | Neurosymbolic | LLM contextual filter | **CodeQL + LLM** (Java) | Batch |
| **Argus** | Academic | LLM-centered multi-agent ensemble | 3-step reachability audit + ReAct PoC | **CodeQL "Re3" loop** + RAG | Batch |
| **OpenAnt** | Knostic (OSS) | 6-stage pipeline, model-per-stage | Adversarial verify + Docker PoC (75.8% confirm) | tree-sitter / native AST | Free OSS scan queue |
| **QASecClaw** | Academic (OSS) | Orchestrator + 5 role agents | LLM SAST-filter, CWE-aware, fail-open | **Semgrep** as scanner | Batch |
| **GitHub Seclab Taskflow** | GitHub (OSS) | YAML-defined taskflows | Multi-stage checklist (no PoC) | **CodeQL** alerts + MCP tools | DB-resumable batch |
| **Cloudflare Glasswing** | Cloudflare | 7-stage directed agent graph | Adversarial Validate agent (diff model) | Cross-repo symbol index | Continuous |
| **Cyber-AutoAgent** | AWS (OSS) | Meta-agent swarm | CTF flag capture | None | Bounded (context rot ~400s) |
| **sast-skills / llm-sast-scanner** | Community (OSS) | Claude Code "skills" (markdown) | Recon→verify per skill; Judge step | None (pure agent skills) | On-demand in IDE/CLI |
| **HexStrike AI** | Community (OSS) | MCP server, 150+ tools | Tool-driven | Wraps nmap/nuclei/etc. as MCP | Interactive |
| **Vigolium** | Vigolium (open-core) | Deterministic modules + `olium` agent runtime | Separate triage pass | 235+ modules | Budget-capped agent |

---

## Dimension A — Harness & orchestration architecture

There are **six recurring harness shapes**. The AppSecSanta survey of 39+ tools names them directly: *single-agent ReAct loop, multi-agent planner-executor, specialized roles, dynamic swarm, MCP-based, and Claude Code native.*

### 1. Coordinator + short-lived swarm (the XBOW/Glasswing pattern)
The highest-end systems refuse to accumulate context in one long-lived agent. **XBOW** runs "thousands of short-lived agents, each with a narrow objective, orchestrated by a persistent coordinator and validated by deterministic logic." Individual agent failures don't compound because each agent is disposable.

**Cloudflare Project Glasswing** is the most explicit public blueprint: a **seven-stage directed graph** — Recon → Hunt → Validate → Gapfill → Dedupe → Trace → Report. The Hunt stage "fires roughly fifty agents in parallel, each pinned to one attack class against one narrow scope," and each hunter "can compile and execute proof-of-concept code in a per-task scratch directory." Their thesis: *"It is a directed graph of agents with deliberately different prompts and deliberately constrained tool access, where the disagreement between agents carries the structural weight."*

**Cyber-AutoAgent** (AWS, on the Strands SDK) implements a "meta-everything" version: a Meta-Agent "deploys dynamic agents as tools, each tailored for specific subtasks with their own reasoning loops."

### 2. Multi-stage sequential pipeline (Aardvark / OpenAnt / deepsec / Argus)
Instead of a swarm, decompose into a fixed sequence of specialized stages:
- **OpenAI Aardvark**: whole-repo analysis → threat model → commit scanning → validation → patch.
- **Knostic OpenAnt**: a **six-stage** pipeline that assigns *a different Claude model per stage* — Sonnet 4 for exposure classification and dynamic exploit generation, Opus 4 for detection and adversarial verification.
- **Vercel deepsec**: a linear, append-only `scan → process → revalidate → enrich → export`, where each stage is an idempotent CLI subcommand reading/writing a consistent on-disk representation.
- **Argus** inverts the traditional design: rather than LLMs assisting SAST, it "decouple[s] the SAST pipeline into different modules and design[s] various agents for them" — dependency scanning, information collecting, PoC generating, data flow scanning, data flow reviewing.

### 3. Role-based planner-executor (specialized crews)
Separate strategy from tactics. In the HPTSA design, "the planner handles strategy, the executors handle tactics. The planner never touches a tool itself." One academic role-based system (CrewAI-orchestrated) uses **Planner / Vulnerability Analyzer / Fixer / Verifier** roles — and notably the Planner is a *rule-based regex scanner, not an LLM*. Ablating that deterministic planner "reduced correct detections by 45%," which is the clearest evidence that **deterministic pre-filtering + LLM analysis beats LLM-only.**

### 4. YAML/config-defined taskflows (GitHub Seclab)
GitHub Security Lab's **Taskflow Agent** makes the pipeline data, not code: "Taskflows are YAML files that describe a series of tasks that we want to do with an LLM." Each task runs with minimal per-task context instead of one monolithic prompt, and `repeat_prompt` templated tasks loop over CodeQL alerts with fresh context per item.

### 5. Claude Code "native" — skills as markdown (the fastest-moving OSS corner)
This is the pattern most relevant to your "skills" question and it's exploding. Agent behavior is encoded as `SKILL.md` markdown files dropped into a folder; "make a .md file, drop it in the right folder, and Claude Code runs it." Transilience Community Tools ships 23 skills + 8 agents. See Dimension B for the anatomy.

### 6. MCP-server-as-harness (HexStrike/AutoPentest)
The agent *is* generic; the capability lives in an MCP server that "wraps security tools as MCP servers... treat[ing] nmap, nuclei, metasploit, and Burp as MCP endpoints with typed input/output schemas." HexStrike AI exposes **150+ tools**; AutoPentest-AI exposes 68+.

**The meta-lesson** (Jamie Lord, "The harness is the product, not the model"): the orchestration layer — tool wiring, loop design, validation scaffolding — is what makes the agent effective, not the base model.

---

## Dimension B — Skills & prompt structure (encoding security knowledge)

How systems inject security expertise splits into three schools:

**1. Per-vulnerability-class specialized prompts.** **Vulnhuntr** ships a tailored secondary prompt for each of seven classes (LFI, AFO, RCE, XSS, SQLI, SSRF, IDOR); class-specific prompts "reduce hallucination and produce PoC exploits." **utkusen/sast-skills** generalizes this into **13 vulnerability skills** run in parallel after a `sast-analysis` skill "maps the technology stack, architecture, entry points, data flows, and trust boundaries." Each skill runs a **two-phase method: "first a recon/discovery phase to find candidate sections, then a verification phase to confirm exploitability"** — i.e., FP reduction is baked into the skill itself.

**2. Language-agnostic reasoning prompts.** **OpenAnt** makes the opposite bet: "the detection prompt is language-agnostic. The same prompt is used across Python, JavaScript/TypeScript, Go, C/C++, Ruby, and PHP" — a three-question prompt (what the code does, where input originates, what security risk arises). Portability over specialization.

**3. Structured severity/focus-area prompts.** **Deriv**'s production Claude Code setup encodes knowledge as an explicit severity-prioritized prompt with enumerated focus areas (input validation, authn/authz, injection, crypto, sensitive-data exposure, race conditions, API security), no external rulesets.

### Anatomy of a Claude Code security skill (`SKILL.md`)
The community has standardized on a consistent shape. A `SKILL.md` contains:
- **YAML frontmatter** — `name` + `description` (the `description` is what the model matches on to decide relevance).
- **Activation triggers** — explicit list of prompts that invoke the skill.
- **Methodology** — step-by-step procedure the agent follows.
- **Output templates**, **script references**, and **authorization gates**.

Notable OSS skill collections:
- **utkusen/sast-skills** — turns Claude Code / Codex / Opencode / Cursor into a SAST scanner; orchestrated by a `CLAUDE.md`/`AGENTS.md` entry point; "no third-party tools required."
- **llm-sast-scanner** — structured **source-to-sink taint analysis across 34 vulnerability classes** (Java/Python/JS-TS/PHP/.NET) with an explicit **"Judge" verification step** to cut false positives.
- **Phoenix Security's security-skills-claude-code** — includes an **OpenGrep Rule Generator** skill that goes "from vulnerability description to validated, production-ready opengrep/semgrep YAML rules with test cases, CWE metadata, and false-positive reduction patterns," generating both **Search rules (structural)** and **Taint rules (source→propagator→sink with sanitizer awareness)**.
- **Trail of Bits' skills** and **Transilience communitytools** — audit-workflow and pentest/bug-bounty skill packs.

---

## Dimension C — Verification & validation (the false-positive battleground)

This is where the real engineering is, because the baseline is dire. Semgrep's benchmark of *un-harnessed* stock agents on 11 real Python apps: **Claude Code (Sonnet 4) 14% TPR / 86% FPR; Codex (o4-mini) 18% TPR / 82% FPR.** Everything below exists to fix that.

### Validator archetypes, weakest → strongest

**1. Confidence scoring (weakest).** Vulnhuntr tiers findings: `<7` unlikely, `7` investigate, `8+` very likely. Cheap, but self-assessed confidence is still the model grading its own homework.

**2. LLM-as-filter / triage agent.** A second LLM re-reads each candidate and votes true/false-positive:
- **QASecClaw**'s SAST Filter Agent builds a CWE-aware prompt (vuln type, CWE, file location, source) per Semgrep finding → cuts FPs **88.6% (560→64)** with only 3.1% recall loss, lifting F1 from 78.4% (raw Semgrep) to **90.9%**. Crucially it uses a **fail-open policy**: if the LLM call fails/times out/returns bad JSON, it *retains* the batch rather than silently dropping findings.
- **Anthropic's claude-code-security-review** ships a dedicated `findings_filter.py` stage that auto-excludes low-signal classes (DoS, rate limiting, generic input validation, open redirects), tunable via a `false-positive-filtering-instructions` file.
- **Semgrep Workflows** wires Claude/OpenAI calls in as built-in steps for "exploitability classification, evidence synthesis, fix generation" — reported 95% human-agreement on findings.

**3. Adversarial disagreement (the high-value pattern).** Instead of one filter, pit two agents against each other. **Cloudflare Glasswing**: "An independent agent with a different prompt, a different model, and no ability to emit its own findings re-reads the code and tries to disprove the hunter." Their explicit finding: *"Putting two agents in deliberate disagreement does more for noise reduction than any amount of careful single-agent prompting."* **OpenAnt**'s verification prompt "requires the model to attempt multiple exploitation approaches before concluding a vulnerability is absent," plus a rule that a valid vuln must harm a party *other than* the attacker.

**4. PoC-in-sandbox execution (the deterministic verifier — strongest).** The principle (René Mayrhofer): *"the best use cases of current GenAI/LLM tools seem to be those that have deterministic verifiers"* — if a claimed vuln is fake, the PoC simply won't fire.
- **OpenAI Aardvark**: "attempt to trigger it in an isolated, sandboxed environment to confirm its exploitability" before reporting.
- **Knostic OpenAnt**: for each candidate an LLM generates a Dockerfile + test script + requirements, runs the exploit in an *ephemeral Docker sandbox*, and classifies CONFIRMED / NOT_REPRODUCED / BLOCKED / INCONCLUSIVE / ERROR — **75.8% dynamic confirmation (144/190)**.
- **XBOW**: "Only issues surviving controlled, non-destructive testing get reported," claiming zero FPs across 1,060+ HackerOne-verified vulns.
- **Vercel deepsec**: the `revalidate` agent "re-reads the code, consults git history (was this fixed?), and emits a verdict: true-positive / false-positive / fixed / uncertain," which "reduces FP rate by 50%+ on most repos."

**5. Static reachability audit.** **Argus** runs a 3-step LLM audit per candidate: end-to-end reachability (control flow, exception handling, validation) → hop-by-hop taint propagation (sanitization/encoding/casting at each hop) → structured export, plus a ReAct PoC agent.

> ⚠️ **Counter-evidence worth internalizing:** the GitHub Seclab team deliberately did *not* build PoC/sandbox validation ("We did not instruct the LLM to validate the results by creating an exploit") and still found ~30 real vulns — proving multi-stage checklist validation can work without execution when you have CodeQL ground truth underneath. And naive tool integration can *hurt*: one role-based paper found adding CodeQL-via-MCP *dropped* detection from 44%→31%. Wiring quality matters more than tool presence.

---

## Dimension D — Static-analysis & MCP tool wiring (Semgrep / Opengrep / CodeQL / tree-sitter)

### Semgrep via MCP — the canonical wiring
The **Semgrep MCP server** is the reference implementation for exposing a SAST engine to an agent as discrete tools:
- `security_check`, `semgrep_scan`, `semgrep_scan_with_custom_rule` (scanning)
- `get_abstract_syntax_tree` (AST extraction)
- `semgrep_findings` (pull from Semgrep AppSec Platform)
- `supported_languages`, `semgrep_rule_schema`
- **Prompts + resources**: a `write_custom_semgrep_rule` prompt plus the rule JSON schema exposed as a resource, so the agent can *author and validate custom rules in the loop.*

Transports: **stdio**, **Streamable HTTP** (`127.0.0.1:8000/mcp`), legacy **SSE** — supporting both local in-process loops and hosted/networked agents. ⚠️ **Currency note:** the standalone `semgrep/mcp` repo was **archived Oct 28 2025**; MCP now ships inside the main `semgrep` binary — target that, not the old repo.

### Opengrep — the open engine agents increasingly wrap
**Opengrep** is the vendor-backed fork of Semgrep (Aikido, Endor Labs, Orca, Jit, Mobb, Arnica, Amplify, Kodem, Legit, Phoenix — 10+ founders), created after Semgrep moved features behind a commercial license. For an AI-SAST builder it matters because it keeps **cross-function taint analysis open-source** (the `--taint-intrafile` flag, higher-order function support) and migrated the engine to **OCaml 5 with shared-memory parallelism** (vs Semgrep's fork-based concurrency) — meaningfully faster and deterministic for large parallel scans. As of 2026 Semgrep and Opengrep's taint engines are **diverging** (Semgrep → cross-file globals/lambdas; Opengrep → per-arity signatures, Elixir/Clojure). The Claude Code skill ecosystem (Phoenix's generator) already emits **opengrep/semgrep-compatible YAML** as a first-class target.

### CodeQL — the neurosymbolic backbone
Where Semgrep dominates the MCP/skill world, CodeQL dominates the academic neurosymbolic work:
- **IRIS**: combines LLMs with CodeQL for Java ("neurosymbolic SAST").
- **Argus "Re3" (Retrieval, Recursion, Review) loop**: CodeQL does forward source→sink search; when a sink is unreachable, a backward-forward recursion builds an upstream call tree, treats its leaves as *surrogate sinks*, and re-runs CodeQL forward — bridging flows pure static analysis misses (reflection, threading, pointer aliasing). This is the most sophisticated LLM↔SAST wiring in the corpus.
- **GitHub Seclab Taskflow**: layers agent triage directly on **CodeQL alerts**, and deliberately pushes *deterministic* checks (trigger parsing, permission validation, file fetch) into **MCP server tools** because "this led to a much more consistent outcome" than LLM reasoning.

### tree-sitter / native AST / parsers
- **OpenAnt**: native AST libs for Python/Go, `ts-morph` for JS/TS, **tree-sitter grammars** for C/C++/Ruby/PHP for code decomposition.
- **Vulnhuntr**: the **Jedi** parser for Python (which pins it to Python 3.10).
- **Codebase-Memory**: tree-sitter parsing → knowledge graph exposed to the LLM through MCP for navigation — the indexing substrate under agentic review.

**Wiring principle across all of them:** delegate anything deterministic (AST, taint paths, permission checks, reachability) to real tools/MCP; reserve the LLM for semantic judgment, business-logic flaws, and exploitability reasoning that pattern engines miss.

---

## Dimension E — Autonomous / long-running / "run-forever" design

"Runs forever" decomposes into four sub-problems, each with an established solution:

**1. State persistence & resumability.**
- **deepsec**: per-file `FileRecord` (candidates, findings, analysisHistory, git metadata); reruns *append* to history and merge via slug+title dedup rather than overwrite. Atomic per-file locking → idempotent, resumable. If a run halts (e.g. out of credits) it "stops gracefully and tells you where to top up," then picks up where it left off.
- **GitHub Seclab Taskflow**: persists intermediate task results in a DB; "we simply rerun the taskflow from the failed task and reuse the results from earlier tasks stored in the database."
- **Aardvark**: builds a **threat model of the whole repo once**, then persists it as the standing context against which every new commit is scanned — state that survives across scans.

**2. Continuous triggering (commit/PR/queue/cron).**
- **Aardvark**: continuously monitors commits; scans each new change against the threat model (plus a historical scan on first connection). Ran "continuously across OpenAI's internal codebases... for months."
- **Anthropic claude-code-security-review**: diff-aware GitHub Action on `pull_request` events; analyzes *only changed files* (`fetch-depth: 2`), caches per commit, 20-min timeout, posts line-level PR comments. Also shipped as a `/security-review` Claude Code slash command.
- **Deriv**: two-workflow GitHub Actions setup — automated review on PR lifecycle events + interactive `@claude` workflow — running continuously across **700+ repos / 5 orgs / ~100+ PRs a week.**
- **Knostic OpenAnt**: operated as a free queue-based scanning service over OSS repos.

**3. Parallel scale.**
- **deepsec**: "runs locally or scales to **1,000+ concurrent Vercel Sandboxes**"; concurrency knobs `--concurrency 5 --batch-size 5` = 25 files in flight; three interchangeable agent backends (Codex, Claude, Earendil Pi) with identical prompt/JSON schemas so you can mix backends per project.
- **Glasswing**: ~50 parallel hunters per run.

**4. Budget / rot control (the thing people forget).** Long-running agents *degrade* as context fills. Cyber-AutoAgent's measured cliff: **"performance significantly degraded after ~400 seconds due to context filling with fuzzing logs, causing the agent to lose focus on its original objectives."** Mitigations in the wild:
- **Vigolium** enforces hard caps on **tokens, tool calls, triage iterations, and wall-clock duration.**
- **XBOW/Glasswing** avoid rot structurally by using *short-lived, disposable* agents that never accumulate context.
- **Taskflow / repeat_prompt** give each item **fresh context** per loop iteration.

**5. The security caveat for autonomous CI agents.** An always-on agent with repo access, secrets, and network is a live attack surface. A real exploit against the Claude Code GitHub Action used **prompt injection hidden in HTML comments in GitHub issues** to make the agent read `/proc/self/environ` and exfiltrate `ANTHROPIC_API_KEY` (patched in Claude Code 2.1.128). Microsoft's design rule — the **"Agents Rule of Two"**: an agent should never *simultaneously* process untrusted input, access secrets, and communicate externally. Anthropic's own repo warns it "is not hardened against prompt injection and should only be used to review trusted PRs."

---

## What to steal if you're building AI-SAST

Concrete, ranked by evidence strength:

1. **Two-agent adversarial validation** (different prompt + different model, validator *cannot emit findings*). Highest ROI per Cloudflare; cheap to add.
2. **Mandatory PoC-in-ephemeral-container** as the terminal gate for high-severity classes (OpenAnt's Dockerfile+script+requirements generation is a copyable recipe). Turns FP filtering into a deterministic check.
3. **Deterministic pre-filter before the LLM** (regex/Semgrep/Opengrep matchers → candidates → LLM investigates only candidates). deepsec's `scan→process` and the CrewAI planner (−45% detection if removed) both prove this.
4. **Per-file idempotent state records** for resumability instead of a global run log (deepsec `FileRecord`). Makes "run forever," resume, and dedup fall out for free.
5. **Wire SAST via MCP with rule-authoring in the loop** (Semgrep MCP's `write_custom_semgrep_rule` + schema resource), and target **Opengrep** for open, parallel, deterministic taint.
6. **Fail-open, not fail-closed** on the LLM validator (QASecClaw) — a flaky model call must not silently delete real findings.
7. **Fresh context per work item + hard budget caps** to dodge the ~400s context-rot cliff.
8. **Encode knowledge as `SKILL.md` skills** if you're on Claude Code — fastest iteration loop, and `sast-skills`/`llm-sast-scanner` are ready-made starting points (13–34 vuln classes, built-in recon→verify).

## Gaps & opportunities

- **Nondeterminism is unsolved.** 3/6/11 findings across identical runs (Semgrep) breaks CI trust; nobody has published a clean fix beyond "run N times and intersect." An open opportunity: consensus/voting harnesses over repeated runs.
- **PoC generation is still weak at the frontier.** SEC-bench Pro: frontier coding agents stay **below 40%** on long-horizon security tasks (best 32% V8 / 38.8% SpiderMonkey); two-agent unions help (37.9% V8) but the validator ceiling is real.
- **Naive tool wiring can regress accuracy** (CodeQL-MCP: 44%→31%). Integration is a first-class engineering problem, not a plug-in.
- **Reachability from *outside* the system is under-served.** Only Glasswing's Trace stage (one agent per consumer repo + cross-repo symbol index) seriously answers "can attacker-controlled input actually reach this?" — a wide-open area.
- **Autonomous-agent security hardening** lags capability (prompt-injection, secret exfiltration). The "Rule of Two" is a constraint, not a solution.

---

## Sources

**Primary / vendor:**
- [protectai/vulnhuntr](https://github.com/protectai/vulnhuntr) · [securityonline writeup](https://securityonline.info/vulnhuntr-a-tool-for-finding-exploitable-vulnerabilities-with-llms-and-static-code-analysis/)
- [XBOW — We Ran 1,060 Autonomous Attacks](https://xbow.com/blog/we-ran-1060-autonomous-attacks)
- [OpenAI — Introducing Aardvark](https://openai.com/index/introducing-aardvark/)
- [anthropics/claude-code-security-review](https://github.com/anthropics/claude-code-security-review)
- [vercel-labs/deepsec](https://github.com/vercel-labs/deepsec) · [architecture.md](https://github.com/vercel-labs/deepsec/blob/main/docs/architecture.md) · [Vercel launch blog](https://vercel.com/blog/introducing-deepsec-find-and-fix-vulnerabilities-in-your-code-base)
- [semgrep/mcp](https://github.com/semgrep/mcp) · [Semgrep Workflows](https://semgrep.dev/products/semgrep-workflows/) · [Semgrep: coding agents as SAST](https://semgrep.dev/blog/2025/finding-vulnerabilities-in-modern-web-apps-using-claude-code-and-openai-codex/)
- [opengrep/opengrep](https://github.com/opengrep/opengrep/) · [Aikido — Opengrep after one year](https://www.aikido.dev/blog/opengrep-sast-one-year) · [AppSecSanta — Semgrep/OpenGrep taint divergence](https://appsecsanta.com/newsletter/2026-w15)
- [GitHub Security Lab — Taskflow Agent](https://github.blog/security/ai-supported-vulnerability-triage-with-the-github-security-lab-taskflow-agent/)
- [Knostic OpenAnt](https://www.knostic.ai/blog/oss-scan) · OpenAnt paper (arXiv 2606.19149)
- [utkusen/sast-skills](https://github.com/utkusen/sast-skills) · [Security-Phoenix-demo/security-skills-claude-code](https://github.com/Security-Phoenix-demo/security-skills-claude-code) · [trailofbits/skills](https://github.com/trailofbits/skills) · [transilienceai/communitytools](https://github.com/transilienceai/communitytools)
- QASecClaw (arXiv 2605.01885) · Argus (arXiv 2604.06633) · Role-based agentic vuln handling (arXiv 2606.14261) · SEC-bench Pro (arXiv 2605.26548)
- [Deriv — Automated security reviews with Claude Code + GitHub Actions](https://derivai.substack.com/p/automated-security-code-reviews-claude-code-github-actions)
- [Microsoft — Securing CI/CD in an agentic world](https://www.microsoft.com/en-us/security/blog/2026/06/05/securing-ci-cd-in-agentic-world-claude-code-github-action-case/)

**Analysis / landscape:**
- [Cloudflare Project Glasswing writeup](https://robotostudio.com/blog/deepsec-audit-future-of-infosec-agents) *(and Cloudflare's directed-agent-graph post)*
- [Jamie Lord — The harness is the product, not the model](https://lord.technology/2026/05/18/the-harness-is-the-product-not-the-model.html)
- [René Mayrhofer — Vulnerability reports and LLMs](https://www.mayrhofer.eu.org/post/vulnerability-reports-and-llms/)
- [Aaron Brown — From Single Agent to Meta-Agent](https://medium.com/data-science-collective/from-single-agent-to-meta-agent-building-the-leading-open-source-autonomous-cyber-agent-e1b704f81707)
- [AppSecSanta — AI Pentesting Agents 2026 (39+ tools)](https://appsecsanta.com/research/ai-pentesting-agents-2026)
- [scadastrangelove/awesome-ai-security-tools](https://github.com/scadastrangelove/awesome-ai-security-tools) · [insidetrust/awesome-ai-pentest](https://github.com/insidetrust/awesome-ai-pentest)
- [Vigolium](https://www.helpnetsecurity.com/2026/05/27/vigolium-open-source-vulnerability-scanner/)

*Note on verification: architecture claims here come from the primary/vendor source for each project. A prior automated research pass extracted and cross-checked these; a minority of arXiv identifiers and dates reflect 2026 preprints as retrieved and were not independently re-verified against a second source.*
