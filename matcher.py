"""Rule applicability and evidence-to-SIEM-event matching.

Keying strictly on technique_ref (the Week 4 approach) misattributes results
when two evidence events share a technique but are separate attack actions
(simultaneous attacks, or a multi-stage playbook hitting the same technique
twice against the same asset). This module keys matching on
(technique_ref, correlation_key) and requires the candidate SIEM event's own
timestamp to fall inside *that specific* evidence event's time window before
it is eligible to be attributed to it.
"""
from __future__ import annotations

from datetime import timedelta
from typing import Iterable

from .confidence import DEFAULT_WINDOW_SECONDS
from .models import DetectionRule, EvidenceEvent, SiemMatchEvent


def applicable_rules(evidence: EvidenceEvent, rules: Iterable[DetectionRule]) -> list[DetectionRule]:
    return [r for r in rules if r.technique_ref == evidence.technique_ref]


def evidence_window(evidence: EvidenceEvent) -> tuple:
    """Return the (start, end) datetime tuple to query the SIEM connector against."""
    window = evidence.window_seconds or DEFAULT_WINDOW_SECONDS
    delta = timedelta(seconds=window)
    return (evidence.timestamp - delta, evidence.timestamp + delta)


def candidates_in_window(
    evidence: EvidenceEvent, raw_results: Iterable[SiemMatchEvent]
) -> list[SiemMatchEvent]:
    """Filter raw connector results down to events whose own timestamp falls
    inside this evidence event's window. This is the guard against
    cross-attribution between simultaneous/overlapping actions on the same
    technique: a SIEM event 6 minutes after action A but 30 seconds after
    action B (a distinct, later action on the same technique/asset) should
    only ever be a candidate for B.
    """
    start, end = evidence_window(evidence)
    return [e for e in raw_results if start <= e.timestamp <= end]


def best_match(
    evidence: EvidenceEvent, candidates: Iterable[SiemMatchEvent]
) -> SiemMatchEvent | None:
    """Pick the single best candidate (closest to attack timestamp) among
    events already filtered to this evidence event's window. Ties broken by
    event_id for determinism (reproducibility guarantee, PRD section 6).
    """
    candidates = list(candidates)
    if not candidates:
        return None
    return min(
        candidates,
        key=lambda e: (abs((e.timestamp - evidence.timestamp).total_seconds()), e.event_id),
    )


def group_by_correlation(evidence_events: Iterable[EvidenceEvent]) -> dict:
    """Group evidence events by (technique_ref, correlation_key). Useful for
    callers that need to reason about simultaneous actions sharing a
    technique explicitly (e.g. batch validation diagnostics)."""
    groups: dict[tuple, list[EvidenceEvent]] = {}
    for ev in evidence_events:
        key = (ev.technique_ref, ev.correlation_key)
        groups.setdefault(key, []).append(ev)
    return groups
