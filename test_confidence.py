from datetime import datetime, timedelta

import pytest

from services.validation_engine.app.confidence import (
    compute_confidence,
    field_match_ratio,
    time_proximity_score,
)
from services.validation_engine.app.models import EvidenceEvent, SiemMatchEvent


def make_evidence(**overrides) -> EvidenceEvent:
    defaults = dict(
        action_id="a1",
        correlation_key="corr-1",
        technique_ref="T1486",
        target_asset_ref="host-1",
        expected_observable="process.name=cipher /e",
        timestamp=datetime(2026, 6, 1, 12, 0, 0),
    )
    defaults.update(overrides)
    return EvidenceEvent(**defaults)


def make_match(**overrides) -> SiemMatchEvent:
    defaults = dict(
        event_id="evt-1",
        vendor="splunk",
        alert_name="Ransomware encryption detected",
        timestamp=datetime(2026, 6, 1, 12, 0, 30),
        fields={"process.name": "cipher /e", "host": "host-1"},
    )
    defaults.update(overrides)
    return SiemMatchEvent(**defaults)


def test_field_match_ratio_full_match():
    evidence = make_evidence()
    match = make_match()
    assert field_match_ratio(evidence.expected_observable, match) == 1.0


def test_field_match_ratio_partial_match():
    evidence = make_evidence(expected_observable="process.name=cipher /e;file.encrypted=true")
    match = make_match(fields={"process.name": "cipher /e"})
    assert field_match_ratio(evidence.expected_observable, match) == 0.5


def test_field_match_ratio_no_expected_observable():
    match = make_match()
    assert field_match_ratio("", match) == 0.0


def test_time_proximity_exact_match():
    ts = datetime(2026, 6, 1, 12, 0, 0)
    assert time_proximity_score(ts, ts, window_seconds=300) == 1.0


def test_time_proximity_decays_linearly():
    attack_ts = datetime(2026, 6, 1, 12, 0, 0)
    event_ts = attack_ts + timedelta(seconds=150)
    assert time_proximity_score(attack_ts, event_ts, window_seconds=300) == pytest.approx(0.5)


def test_time_proximity_outside_window_floors_at_zero():
    attack_ts = datetime(2026, 6, 1, 12, 0, 0)
    event_ts = attack_ts + timedelta(seconds=600)
    assert time_proximity_score(attack_ts, event_ts, window_seconds=300) == 0.0


def test_compute_confidence_no_match_is_zero():
    evidence = make_evidence()
    assert compute_confidence(evidence, None, ["splunk"]) == 0.0


def test_compute_confidence_perfect_match_is_high():
    evidence = make_evidence(timestamp=datetime(2026, 6, 1, 12, 0, 0))
    match = make_match(timestamp=datetime(2026, 6, 1, 12, 0, 0), vendor="splunk")
    score = compute_confidence(evidence, match, ["splunk"])
    assert score >= 0.95


def test_compute_confidence_weak_field_match_and_late_alert_is_partial_range():
    evidence = make_evidence(
        expected_observable="process.name=cipher /e;file.encrypted=true;vssadmin_deleted=true",
        timestamp=datetime(2026, 6, 1, 12, 0, 0),
    )
    # Only 1 of 3 sub-observables present, and matched far from the attack timestamp.
    match = make_match(
        fields={"process.name": "cipher /e"},
        timestamp=datetime(2026, 6, 1, 12, 4, 30),
        vendor="qradar",
    )
    score = compute_confidence(evidence, match, ["splunk", "qradar"])
    assert 0.1 <= score <= 0.4


def test_compute_confidence_never_exceeds_one_or_below_zero():
    evidence = make_evidence()
    match = make_match()
    score = compute_confidence(evidence, match, ["splunk"])
    assert 0.0 <= score <= 1.0
