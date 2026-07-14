"""Core data contracts for Crucible.

Two models everything else depends on:

- ``Finding``   — a SARIF-aligned vulnerability finding carried through the
  validation ladder, annotated with a confirmation status and stability score.
- ``FileRecord`` — per-file, append-only state enabling idempotent, resumable
  ("run forever") scans.
"""

from crucible.schema.finding import (
    ConfirmationStatus,
    Finding,
    Location,
    Severity,
    StabilityScore,
    ValidationVerdict,
)
from crucible.schema.state import FileRecord, ScanState

__all__ = [
    "ConfirmationStatus",
    "Finding",
    "Location",
    "Severity",
    "StabilityScore",
    "ValidationVerdict",
    "FileRecord",
    "ScanState",
]
