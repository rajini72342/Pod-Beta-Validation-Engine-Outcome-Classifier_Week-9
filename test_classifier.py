from services.outcome_classifier.app.classifier import OutcomeClassifier


def make_result(**overrides) -> dict:
    defaults = dict(
        action_id="a1",
        confidence=0.9,
        rule_id="r1",
        technique_ref="T1486",
        matched_events=[{"event_id": "e1"}],
        no_data=False,
        causal_chain=["Evidence event received: a1", "Rule executed: r1"],
        mttd_seconds=12.5,
    )
    defaults.update(overrides)
    return defaults


def test_detected_verdict_above_threshold():
    classifier = OutcomeClassifier()
    verdict = classifier.classify(make_result(confidence=0.85))
    assert verdict.verdict == "Detected"
    assert verdict.alert_fidelity in ("high", "medium")
    assert verdict.mttd_seconds == 12.5


def test_partial_verdict_in_middle_band():
    classifier = OutcomeClassifier()
    verdict = classifier.classify(make_result(confidence=0.45))
    assert verdict.verdict == "Partial"
    assert verdict.alert_fidelity == "medium"


def test_missed_verdict_low_confidence():
    classifier = OutcomeClassifier()
    verdict = classifier.classify(make_result(confidence=0.1, matched_events=[], mttd_seconds=None))
    assert verdict.verdict == "Missed"
    assert verdict.alert_fidelity is None
    assert verdict.mttd_seconds is None


def test_no_data_verdict_when_no_telemetry():
    classifier = OutcomeClassifier()
    verdict = classifier.classify(
        make_result(confidence=0.0, matched_events=[], no_data=True, mttd_seconds=None)
    )
    assert verdict.verdict == "NoData"
    assert verdict.alert_fidelity is None


def test_causal_chain_never_empty():
    classifier = OutcomeClassifier()
    verdict = classifier.classify(make_result(causal_chain=[]))
    assert len(verdict.causal_chain) >= 1


def test_threshold_boundaries_are_inclusive():
    classifier = OutcomeClassifier()
    exactly_detected = classifier.classify(make_result(confidence=0.7))
    exactly_partial = classifier.classify(make_result(confidence=0.3))
    just_below_partial = classifier.classify(make_result(confidence=0.29, matched_events=[]))

    assert exactly_detected.verdict == "Detected"
    assert exactly_partial.verdict == "Partial"
    assert just_below_partial.verdict == "Missed"
