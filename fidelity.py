"""Alert fidelity heuristic (high/medium/low) for Detected verdicts.

Flagged in the code review as a placeholder pending real noisy-alert sample
data (see docs/CODE_REVIEW_validation_engine_outcome_classifier.md, Outstanding
follow-ups). Current heuristic: fidelity tracks confidence banding within the
Detected range, plus a small penalty if the match came from field-name
matching only (no connector agreement), since single-connector alerts are
easier to be a coincidental match on a noisy rule.
"""
from __future__ import annotations


def assess_fidelity(confidence: float, connector_agreement_present: bool) -> str:
    if confidence >= 0.9 and connector_agreement_present:
        return "high"
    if confidence >= 0.8:
        return "high" if connector_agreement_present else "medium"
    if confidence >= 0.7:
        return "medium"
    return "low"
