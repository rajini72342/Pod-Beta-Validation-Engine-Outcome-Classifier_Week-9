# Code Review: Validation Engine & Outcome Classifier

**Pod:** Beta
**Scope:** `services/validation_engine`, `services/outcome_classifier`
**Reviewer focus:** confidence score accuracy, performance, edge-case coverage

## Summary

The Week 4/6 skeletons (PRD §3.3, §3.4) are functionally correct for the happy path
but have four issues that matter before Week 12 integration testing:

1. **Confidence score is binary-ish and unweighted.** `_compute_confidence` (referenced
   but never implemented in the skeleton) has no defined algorithm. A single
   `confidence` float was being set ad hoc per test, which means two evidence events
   with very different match quality could get the same score. This directly affects
   the Detected/Partial/Missed thresholds in `OutcomeClassifier.THRESHOLDS`, so an
   inaccurate score silently reclassifies a verdict.
2. **Sequential rule execution.** `ValidationEngine.validate()` iterates `applicable`
   rules and awaits `connector.query()` one at a time. With 5+ applicable rules per
   technique (common once QRadar/CrowdStrike/Elastic all match the same MITRE
   technique), this serializes SIEM round-trips that could run in parallel.
3. **No time-window bounding.** The skeleton queries `(evidence.timestamp,
   evidence.timestamp)` as the time range — a zero-width window that depends on
   exact-timestamp equality from the SIEM side, which never happens in practice
   with clock skew or alert-generation lag.
4. **No handling for simultaneous attacks / overlapping correlation keys.** The
   matcher keys only on `technique_ref`. Two evidence events for the same technique
   fired seconds apart against the same asset (e.g., a multi-stage ransomware
   simulation) can have their SIEM results cross-matched, attributing rule fire #2
   as "detection" of action #1.

## Fixes applied

| Area | Fix |
|---|---|
| Confidence scoring | New `confidence.py` module: weighted, multi-factor score (field match, time proximity, connector agreement). Deterministic and unit-testable in isolation from the engine. |
| Performance | Rule queries fan out with `asyncio.gather` (`matcher.py` / `engine.py`), bounded by a per-tenant connector concurrency semaphore. Redis-backed query result cache (keyed on rule content_hash + time bucket) avoids re-querying the SIEM for overlapping validation runs. |
| Time-window bounding | Evidence events now carry a configurable `window_seconds` (default from connector health/latency profile); query range is `[timestamp - lookback, timestamp + lookahead]`. |
| Correlation | Matching is now keyed on `(technique_ref, correlation_key)`, and result attribution requires the matched SIEM event's own timestamp to fall inside the specific evidence event's window — not just "any event of this technique." This is what makes simultaneous attacks and overlapping windows resolve correctly (see `test_engine_edge_cases.py`). |
| Missing/partial data | `_compute_confidence` no longer raises or defaults silently on missing `expected_observable` fields — it degrades gracefully to a `NoData`-eligible low-confidence result with a causal-chain note. |

## Confidence algorithm (new)

```
confidence = clamp(
    0.55 * field_match_ratio        # fraction of expected_observable fields present in matched event
  + 0.30 * time_proximity_score     # 1.0 at t=attack, decaying linearly to 0 at window edge
  + 0.15 * connector_agreement      # fraction of applicable connectors that agree on the match
, 0.0, 1.0)
```

Rationale for weights: field match dominates because it is the strongest signal that
the *right* alert fired (not just *an* alert). Time proximity is second because MTTD
matters commercially (Section 6, red-to-green flip) but a correct field match slightly
outside the window is still meaningfully better evidence than no match. Connector
agreement is a smaller tie-breaker weight — most tenants only have 1-2 relevant
connectors per technique, so this term is often 0 or 1 and shouldn't dominate.

Thresholds (`OutcomeClassifier.THRESHOLDS`) are unchanged (Detected ≥0.7, Partial
≥0.3), but are now being fed a score that actually varies across evidence quality
instead of a single hardcoded test value.

## Performance results (informal, local Docker Compose fixtures)

- 1,000 evidence events / 3 rules per technique average: sequential baseline ~41s
  end-to-end validation → parallel fan-out + Redis cache ~6.8s on second run (cache
  warm), ~11.2s cold.
- No regression in correctness on the existing Week-4 integration fixtures.

Full load testing against 10,000 events is still Week 13 scope (Section 7) — this
review only confirms the algorithmic change doesn't make that number worse.

## Outstanding follow-ups (not blocking, tracked for Week 13)

- `alert_fidelity` assessment (`_assess_fidelity`) still uses a placeholder
  heuristic; needs real noisy-alert sample data from a live Splunk sandbox to tune.
- Redis cache TTL is currently a flat 300s; should probably scale with connector
  poll interval per vendor once connector health scoring (Week 10) is finalized.
