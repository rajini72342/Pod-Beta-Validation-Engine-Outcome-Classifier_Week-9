"""Outcome Classifier (PRD section 3.4), optimized per Week 11 code review.

Takes a RawValidationResult (dict, matching validation_engine.models) and
produces an OutcomeVerdict. Thresholds match the PRD table:
  Detected: 0.7-1.0   Partial: 0.3-0.6   Missed: 0.0-0.2   NoData: N/A
"""
from __future__ import annotations

from .causal_chain import build_causal_chain
from .fidelity import assess_fidelity
from .models import OutcomeVerdict


class OutcomeClassifier:
    THRESHOLDS = {"detected": 0.7, "partial": 0.3}

    def classify(self, validation_result: dict) -> OutcomeVerdict:
        chain = build_causal_chain(validation_result)
        conf = validation_result["confidence"]
        no_data = validation_result.get("no_data", False)
        matched_events = validation_result.get("matched_events") or []
        connector_agreement_present = len(matched_events) > 0

        if no_data and not matched_events:
            verdict = "NoData"
            fidelity = None
        elif conf >= self.THRESHOLDS["detected"]:
            verdict = "Detected"
            fidelity = assess_fidelity(conf, connector_agreement_present)
        elif conf >= self.THRESHOLDS["partial"]:
            verdict = "Partial"
            fidelity = "medium"
        else:
            verdict = "Missed"
            fidelity = None

        mttd = validation_result.get("mttd_seconds") if verdict in ("Detected", "Partial") else None

        return OutcomeVerdict(
            action_id=validation_result["action_id"],
            verdict=verdict,
            confidence=conf,
            causal_chain=chain,
            mttd_seconds=mttd,
            alert_fidelity=fidelity,
            rule_id=validation_result.get("rule_id", "NONE"),
            technique_ref=validation_result.get("technique_ref", ""),
        )
