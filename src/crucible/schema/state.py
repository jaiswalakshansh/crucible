"""Per-file, append-only scan state — the substrate for resumable "run forever".

Following the deepsec pattern: the unit of work is a *source file*, not a
finding. Each ``FileRecord`` holds the file's candidates, confirmed findings, and
an append-only ``analysis_history``. Reruns *merge* by fingerprint rather than
overwrite, so a scan can stop at any point (out of budget, tool crash, Ctrl-C)
and resume without losing or duplicating work.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from crucible.schema.finding import Finding


@dataclass
class AnalysisEntry:
    """One pass over a file. Appended, never mutated."""

    stage: str                      # e.g. "scan", "hunt", "revalidate"
    run_id: str                     # groups entries from a single crucible invocation
    blob_sha: str                   # git blob / content hash the pass ran against
    summary: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "stage": self.stage,
            "run_id": self.run_id,
            "blob_sha": self.blob_sha,
            "summary": self.summary,
        }


@dataclass
class FileRecord:
    """Idempotent, mergeable state for a single source file."""

    path: str
    blob_sha: str = ""
    findings: list[Finding] = field(default_factory=list)
    analysis_history: list[AnalysisEntry] = field(default_factory=list)

    def merge_findings(self, incoming: list[Finding]) -> int:
        """Merge new findings by fingerprint; return count of genuinely new ones.

        Existing findings are kept (their accumulated verdicts/evidence are more
        advanced than a fresh detection's). This makes reruns additive.
        """
        seen = {f.fingerprint for f in self.findings}
        added = 0
        for f in incoming:
            if f.fingerprint not in seen:
                self.findings.append(f)
                seen.add(f.fingerprint)
                added += 1
        return added

    def record_pass(self, entry: AnalysisEntry) -> None:
        self.analysis_history.append(entry)

    def already_analyzed(self, stage: str, blob_sha: str) -> bool:
        """True if this exact stage already ran against this exact content.

        The resumability check: skip work that a prior (possibly interrupted)
        run already completed on unchanged content.
        """
        return any(
            e.stage == stage and e.blob_sha == blob_sha
            for e in self.analysis_history
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "blob_sha": self.blob_sha,
            "findings": [f.to_sarif_result() for f in self.findings],
            "analysis_history": [e.to_dict() for e in self.analysis_history],
        }


@dataclass
class ScanState:
    """Whole-scan state: a map of path -> FileRecord, plus run metadata.

    Persistence format is deliberately simple (one JSON doc, or one file per
    record) so it is trivially inspectable and diff-able. A real backend can
    swap in SQLite/Postgres without changing this interface.
    """

    run_id: str
    root: str
    records: dict[str, FileRecord] = field(default_factory=dict)

    def record_for(self, path: str) -> FileRecord:
        rec = self.records.get(path)
        if rec is None:
            rec = FileRecord(path=path)
            self.records[path] = rec
        return rec

    @property
    def all_findings(self) -> list[Finding]:
        out: list[Finding] = []
        for rec in self.records.values():
            out.extend(rec.findings)
        return out

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "root": self.root,
            "records": {p: r.to_dict() for p, r in self.records.items()},
        }
