"""The ``Finding`` data contract — SARIF-aligned, ladder-aware.

Crucible speaks SARIF at its boundaries (Opengrep, Semgrep, and CodeQL all emit
it), but internally a finding also carries the two honesty signals that are core
to the project:

- ``confirmation``: whether the finding was *proven* (a PoC fired in a sandbox),
  merely *suspected*, or refuted. We never present suspected as proven.
- ``stability``: how reproducible the finding was across independent runs — the
  bounded, *reported* answer to LLM nondeterminism rather than a hidden failure.

The mapping to/from SARIF lives here so no other layer needs to know the wire
format. See ``to_sarif_result`` / ``from_sarif_result``.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field, asdict
from typing import Any


class Severity(enum.Enum):
    """Normalized severity. SARIF uses ``level`` (error/warning/note); we keep a
    finer security-oriented scale and map it on export."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    def to_sarif_level(self) -> str:
        return {
            Severity.CRITICAL: "error",
            Severity.HIGH: "error",
            Severity.MEDIUM: "warning",
            Severity.LOW: "note",
            Severity.INFO: "note",
        }[self]


class ConfirmationStatus(enum.Enum):
    """Where a finding sits on the proof spectrum after the validation ladder.

    Only ``CONFIRMED`` means an exploit actually fired in a sandbox. Everything
    else is surfaced as suspected — never dressed up as certain.
    """

    CONFIRMED = "confirmed"            # PoC fired in sandbox (deterministic proof)
    SUSPECTED = "suspected"            # survived reasoning gates, no executed PoC
    NOT_REPRODUCED = "not_reproduced"  # PoC attempted, did not fire
    REFUTED = "refuted"                # adversarial validator disproved it
    INCONCLUSIVE = "inconclusive"      # a gate errored/timed out -> kept (fail-open)


class ValidationGate(enum.Enum):
    """The five gates of the ladder, cheapest -> strongest."""

    DETERMINISTIC_PREFILTER = "deterministic_prefilter"
    ADVERSARIAL_DISPROOF = "adversarial_disproof"
    REACHABILITY_AUDIT = "reachability_audit"
    POC_SANDBOX = "poc_sandbox"
    CONSENSUS_VOTE = "consensus_vote"


@dataclass
class ValidationVerdict:
    """One gate's verdict on a finding. The ladder appends these in order."""

    gate: ValidationGate
    passed: bool
    detail: str = ""
    # Fail-open marker: True when the gate could not run (error/timeout) and the
    # finding was retained rather than dropped.
    failed_open: bool = False

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["gate"] = self.gate.value
        return d


@dataclass
class StabilityScore:
    """Bounded, reported answer to LLM nondeterminism.

    ``confirmed_runs`` of ``total_runs`` independent runs surfaced this finding.
    A single-run scan has ``total_runs == 1`` and ``ratio == 1.0`` with the
    caveat that stability is simply unmeasured — surfaced honestly via ``measured``.
    """

    confirmed_runs: int = 1
    total_runs: int = 1

    @property
    def ratio(self) -> float:
        return self.confirmed_runs / self.total_runs if self.total_runs else 0.0

    @property
    def measured(self) -> bool:
        return self.total_runs > 1

    def to_dict(self) -> dict[str, Any]:
        return {
            "confirmed_runs": self.confirmed_runs,
            "total_runs": self.total_runs,
            "ratio": round(self.ratio, 4),
            "measured": self.measured,
        }


@dataclass
class Location:
    """A source location. Mirrors SARIF ``physicalLocation``."""

    path: str
    start_line: int
    end_line: int | None = None
    start_col: int | None = None
    end_col: int | None = None

    def to_sarif(self) -> dict[str, Any]:
        region: dict[str, Any] = {"startLine": self.start_line}
        if self.end_line is not None:
            region["endLine"] = self.end_line
        if self.start_col is not None:
            region["startColumn"] = self.start_col
        if self.end_col is not None:
            region["endColumn"] = self.end_col
        return {
            "physicalLocation": {
                "artifactLocation": {"uri": self.path},
                "region": region,
            }
        }

    @classmethod
    def from_sarif(cls, loc: dict[str, Any]) -> "Location":
        phys = loc.get("physicalLocation", {})
        region = phys.get("region", {})
        return cls(
            path=phys.get("artifactLocation", {}).get("uri", ""),
            start_line=region.get("startLine", 0),
            end_line=region.get("endLine"),
            start_col=region.get("startColumn"),
            end_col=region.get("endColumn"),
        )


@dataclass
class Finding:
    """A vulnerability finding as it travels through Crucible.

    ``rule_id`` + primary location define identity for dedup/merge across reruns
    (see ``FileRecord``). ``confirmation`` and ``stability`` are the honesty
    signals that always ride along to the user.
    """

    rule_id: str
    message: str
    severity: Severity
    location: Location
    # Provenance: which detector/agent first surfaced this (e.g. "opengrep",
    # "hunter:sql-injection"). Enables A/B'ing sources.
    source: str = "unknown"
    cwe: str | None = None
    confirmation: ConfirmationStatus = ConfirmationStatus.SUSPECTED
    stability: StabilityScore = field(default_factory=StabilityScore)
    verdicts: list[ValidationVerdict] = field(default_factory=list)
    # Free-form structured evidence accumulated by the ladder (taint path,
    # reachability notes, PoC transcript, ...).
    evidence: dict[str, Any] = field(default_factory=dict)

    @property
    def fingerprint(self) -> str:
        """Stable identity for dedup/merge: rule + file + start line."""
        return f"{self.rule_id}::{self.location.path}::{self.location.start_line}"

    def to_sarif_result(self) -> dict[str, Any]:
        """Render as a single SARIF ``result`` object."""
        props: dict[str, Any] = {
            "crucible/source": self.source,
            "crucible/confirmation": self.confirmation.value,
            "crucible/stability": self.stability.to_dict(),
            "crucible/verdicts": [v.to_dict() for v in self.verdicts],
        }
        if self.evidence:
            props["crucible/evidence"] = self.evidence
        result: dict[str, Any] = {
            "ruleId": self.rule_id,
            "level": self.severity.to_sarif_level(),
            "message": {"text": self.message},
            "locations": [self.location.to_sarif()],
            "properties": props,
        }
        if self.cwe:
            result["properties"]["crucible/cwe"] = self.cwe
        return result

    @classmethod
    def from_sarif_result(
        cls, result: dict[str, Any], *, source: str = "sarif"
    ) -> "Finding":
        """Parse a SARIF ``result`` (e.g. straight from Opengrep) into a Finding.

        Severity is read from ``level`` when a richer Crucible property is absent.
        """
        level = result.get("level", "warning")
        severity = {
            "error": Severity.HIGH,
            "warning": Severity.MEDIUM,
            "note": Severity.LOW,
            "none": Severity.INFO,
        }.get(level, Severity.MEDIUM)
        locations = result.get("locations") or [{}]
        props = result.get("properties", {})
        return cls(
            rule_id=result.get("ruleId", "unknown"),
            message=(result.get("message") or {}).get("text", ""),
            severity=severity,
            location=Location.from_sarif(locations[0]),
            source=source,
            cwe=props.get("crucible/cwe") or props.get("cwe"),
        )
