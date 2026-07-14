"""Scoring: compare predicted findings against labeled ground truth.

A prediction matches a ground-truth label when they share the same file path and
the predicted line falls within the label's line span (inclusive). This tolerance
is a design choice: exact-line matching is too brittle for LLM output, span
matching is a defensible middle ground. It is documented here rather than hidden.

All functions are pure and deterministic; tests/test_scoring.py checks the counts
and the metric arithmetic against hand-computed values.
"""

from __future__ import annotations

from dataclasses import dataclass

from crucible.schema.finding import Finding


@dataclass(frozen=True)
class Label:
    """A ground-truth vulnerability location."""

    path: str
    start_line: int
    end_line: int | None = None

    def contains(self, path: str, line: int) -> bool:
        if path != self.path:
            return False
        end = self.end_line if self.end_line is not None else self.start_line
        return self.start_line <= line <= end


@dataclass(frozen=True)
class Score:
    tp: int
    fp: int
    fn: int

    @property
    def precision(self) -> float:
        denom = self.tp + self.fp
        return self.tp / denom if denom else 0.0

    @property
    def recall(self) -> float:
        denom = self.tp + self.fn
        return self.tp / denom if denom else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0

    def to_dict(self) -> dict[str, float | int]:
        return {
            "tp": self.tp,
            "fp": self.fp,
            "fn": self.fn,
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1": round(self.f1, 4),
        }


def score_findings(predictions: list[Finding], labels: list[Label]) -> Score:
    """Count true/false positives and false negatives.

    - A label is a true positive if at least one prediction falls within it.
    - A prediction is a false positive if it matches no label.
    - A label with no matching prediction is a false negative.

    Multiple predictions inside one label count as a single true positive (the
    label is satisfied once); the extra predictions are not counted as false
    positives, since they point at a real issue. This is a deliberate, documented
    choice — a stricter scheme would penalize duplicates.
    """
    matched_labels: set[int] = set()
    fp = 0
    for pred in predictions:
        hit = False
        for i, label in enumerate(labels):
            if label.contains(pred.location.path, pred.location.start_line):
                matched_labels.add(i)
                hit = True
        if not hit:
            fp += 1
    tp = len(matched_labels)
    fn = len(labels) - tp
    return Score(tp=tp, fp=fp, fn=fn)
