"""The coordinator — decides scope and dispatches; never touches tools itself.

Phase 0 wires the smallest honest end-to-end path: enumerate files, run the
Opengrep floor when available, merge candidates into per-file state. Each later
stage (hunt fan-out, the validation ladder, trace, dedup) slots into ``run`` as
it is implemented and A/B-measured.
"""

from __future__ import annotations

import enum
import os

from crucible.schema.finding import Finding
from crucible.schema.state import AnalysisEntry, ScanState
from crucible.substrate.languages import detect_language
from crucible.substrate.opengrep import OpengrepAdapter


class Stage(enum.Enum):
    RECON = "recon"
    SLICE = "slice"
    HUNT = "hunt"
    VALIDATE = "validate"
    TRACE = "trace"
    DEDUP = "dedup"
    REPORT = "report"


class Coordinator:
    def __init__(self, run_id: str, *, use_opengrep: bool = True) -> None:
        self.run_id = run_id
        self.use_opengrep = use_opengrep
        self.opengrep = OpengrepAdapter()

    def enumerate_files(self, root: str) -> list[str]:
        """Walk ``root``, returning source files in a supported language.
        Skips VCS/dependency dirs; unknown extensions are simply not returned."""
        skip = {".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build"}
        out: list[str] = []
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in skip]
            for name in filenames:
                path = os.path.join(dirpath, name)
                if detect_language(path) is not None:
                    out.append(path)
        return out

    def run(self, root: str) -> ScanState:
        """Phase 0 pipeline: RECON only (Opengrep floor -> per-file state).

        Returns a populated ``ScanState``. Later phases extend this method with
        the hunt fan-out and the validation ladder; the state contract does not
        change.
        """
        state = ScanState(run_id=self.run_id, root=root)
        files = self.enumerate_files(root)

        opengrep_findings: list[Finding] = []
        if self.use_opengrep and self.opengrep.available():
            try:
                opengrep_findings = self.opengrep.scan(root)
            except Exception:
                # Fail-open at the substrate too: a scanner crash must not abort
                # the run. Downstream LLM recon still applies.
                opengrep_findings = []

        by_path: dict[str, list[Finding]] = {}
        for f in opengrep_findings:
            by_path.setdefault(f.location.path, []).append(f)

        for path in files:
            rec = state.record_for(path)
            rec.merge_findings(by_path.get(path, []))
            rec.record_pass(
                AnalysisEntry(
                    stage=Stage.RECON.value,
                    run_id=self.run_id,
                    blob_sha=rec.blob_sha,
                    summary=f"opengrep candidates: {len(by_path.get(path, []))}",
                )
            )
        return state
