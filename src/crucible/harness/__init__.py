"""L2 — the harness (orchestration).

Coordinator + short-lived agent swarm, expressed as a DAG of stages:

    Recon -> Slice -> Hunt(fan-out) -> Validate(ladder) -> Trace -> Dedup -> Report

The coordinator decides scope and dispatches; it never touches tools directly
(planner/executor separation). Hunt fans out disposable agents, each pinned to
one attack class on one narrow code slice with fresh context, which is how we
avoid long-context "rot". Phase 0 provides the coordinator skeleton and stage
enum; fan-out execution lands in Phase 1.
"""

from crucible.harness.coordinator import Coordinator, Stage

__all__ = ["Coordinator", "Stage"]
