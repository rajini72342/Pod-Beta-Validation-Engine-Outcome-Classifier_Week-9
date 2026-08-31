"""Weighted, multi-factor confidence scoring for the Validation Engine.

Replaces the ad hoc single-value confidence in the Week 4 skeleton with a
deterministic, unit-testable function. See docs/CODE_REVIEW_validation_engine_outcome_classifier.md
for the rationale behind the weights.
"""
from __future__ import annotations

from datetime import datetime
from typing import Iterable

from .models import EvidenceEvent, SiemMatchEvent

FIELD_MATCH_WEIGHT = 0.55
TIME_PROXIMITY_WEIGHT = 0.30
CONNECTOR_AGREEMENT_WEIGHT = 0.15

DEFAULT_WINDOW_SECONDS = 300  # 5 minutes either side, if not set on the evidence event


def _clamp(value: float, lo: float = 0.0, hi: float = 1.0) -> float:
    return max(lo, min(hi, value))


def field_match_ratio(expected_observable: str, matched_event: SiemMatchEvent) -> float:
    """Fraction of the expected observable's tokens present in the matched event's fields.

    expected_observable is a small DSL-free string such as "process.name=cipher /e"
    or "file.encrypted=true;process.name=vssadmin.exe". We split on ';' for multiple
    expected sub-observables and check presence in the normalised OCSF field bag.
    """
    if not expected_observable:
        return 0.0

    sub_observables = [tok.strip() for tok in expected_observable.split(";") if tok.strip()]
    if not sub_observables:
        return 0.0

    field_blob = " ".join(f"{k}={v}" for k, v in matched_event.fields.items()).lower()
    # Also allow a match against alert_name for connectors that don't populate fields.
    if matched_event.alert_name:
        field_blob += " " + matched_event.alert_name.lower()

    hits = sum(1 for tok in sub_observables if tok.lower() in field_blob)
    return hits / len(sub_observables)


def time_proximity_score(attack_ts: datetime, event_ts: datetime, window_seconds: int) -> float:
    """1.0 at exact match, decaying linearly to 0.0 at the edge of the window.

    Returns 0.0 (not negative) once outside the window — callers are expected to
    have already excluded out-of-window events from matching entirely (see
    matcher.py), so this is a defensive floor, not the primary filter.
    """
    if window_seconds <= 0:
        return 1.0 if attack_ts == event_ts else 0.0
    delta = abs((event_ts - attack_ts).total_seconds())
    if delta >= window_seconds:
        return 0.0
    return 1.0 - (delta / window_seconds)


def connector_agreement(matched_event: SiemMatchEvent, all_candidate_vendors: Iterable[str]) -> float:
    """Fraction of applicable connectors/vendors that produced a matching event.

    Callers pass the full set of vendors that had an applicable rule for this
    technique; this function is evaluated once per best-matched event, so it
    reflects "did other connectors also see it" rather than being recomputed
    per-connector.
    """
    vendors = list(dict.fromkeys(all_candidate_vendors))  # de-dupe, preserve order
    if not vendors:
        return 0.0
    return 1.0 if matched_event.vendor in vendors else 0.0


def compute_confidence(
    evidence: EvidenceEvent,
    matched_event: SiemMatchEvent | None,
    all_candidate_vendors: Iterable[str],
) -> float:
    """Top-level entry point used by the Validation Engine.

    Returns 0.0 (not an error) when there is no matched_event — this is the
    correct behaviour for a Missed verdict, and the Outcome Classifier handles
    the No Data case separately based on whether the SIEM returned any results
    at all vs. returned results that didn't match.
    """
    if matched_event is None:
        return 0.0

    window = evidence.window_seconds or DEFAULT_WINDOW_SECONDS

    fmr = field_match_ratio(evidence.expected_observable, matched_event)
    tps = time_proximity_score(evidence.timestamp, matched_event.timestamp, window)
    ca = connector_agreement(matched_event, all_candidate_vendors)

    score = (
        FIELD_MATCH_WEIGHT * fmr
        + TIME_PROXIMITY_WEIGHT * tps
        + CONNECTOR_AGREEMENT_WEIGHT * ca
    )
    return round(_clamp(score), 4)
