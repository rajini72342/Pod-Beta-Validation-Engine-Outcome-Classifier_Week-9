"""Pydantic models for the Validation Engine (PRD section 3.3)."""
from __future__ import annotations

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field


class EvidenceEvent(BaseModel):
    action_id: str
    correlation_key: str
    technique_ref: str  # MITRE ATT&CK technique id, e.g. 'T1486'
    target_asset_ref: str
    expected_observable: str
    timestamp: datetime
    # Optional per-action override; falls back to connector-profile default.
    window_seconds: Optional[int] = None


class DetectionRule(BaseModel):
    rule_id: str
    content_hash: str
    vendor: str  # splunk, sentinel, elastic, qradar, crowdstrike
    technique_ref: str
    query_str: str


class SiemMatchEvent(BaseModel):
    """A single raw/normalised (OCSF) event returned by a connector query."""
    event_id: str
    vendor: str
    alert_name: Optional[str] = None
    timestamp: datetime
    fields: dict = Field(default_factory=dict)  # normalised OCSF fields present on the alert


class RawValidationResult(BaseModel):
    """Intermediate result before classification into a Verdict."""
    action_id: str
    rule_id: str
    technique_ref: str
    confidence: float
    matched_events: list[SiemMatchEvent] = Field(default_factory=list)
    no_data: bool = False
    causal_chain: list[str] = Field(default_factory=list)
    mttd_seconds: Optional[float] = None


class Verdict(BaseModel):
    action_id: str
    verdict: str  # Detected, Missed, Partial, NoData
    confidence: float
    mttd_seconds: Optional[float] = None
    matched_evidence_ref: Optional[str] = None
    causal_chain: list[str] = Field(default_factory=list)
    rule_id: str
    technique_ref: str
