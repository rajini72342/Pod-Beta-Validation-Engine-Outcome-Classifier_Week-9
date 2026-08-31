# Validation Engine Configuration Guide

**Module:** CyBreach Module 2 (The Validator) — Pod Beta
**Services covered:** Validation Engine, Outcome Classifier
**Audience:** Fresher developers configuring or tuning a deployed instance

---

## 1. Overview

The Validation Engine takes evidence events (from Module 1) and detection rules
(from the Rule Ingestion Service), queries the tenant's SIEM connectors, and
produces a `RawValidationResult` per evidence event. The Outcome Classifier
turns that raw result into a `Verdict` (Detected / Missed / Partial / NoData).

This guide covers the configuration knobs added during the Week 11 code
review: time windows, confidence weights, cache TTLs, and connector
concurrency. It assumes you've already read PRD sections 3.3 and 3.4.

## 2. Time window configuration

Every evidence event is validated against a time window centered on its
`timestamp`. The window is used two ways:

1. To bound the SIEM query range (`matcher.evidence_window`).
2. To score how close a matched alert is to the attack time
   (`confidence.time_proximity_score`).

| Setting | Default | Where | Notes |
|---|---|---|---|
| `window_seconds` | 300 (5 min) | Per evidence event, optional field | Overrides the default for one action. Use for slow-to-alert techniques (e.g. batch log analysis rules) where 5 minutes is too tight. |
| `DEFAULT_WINDOW_SECONDS` | 300 | `confidence.py` module constant | Tenant-wide default when the evidence event doesn't set one. |

**How to choose a window:** the window should be at least as wide as the
slowest connector's expected alert latency for the techniques you're
validating (see connector health / query latency in the SIEM Compatibility
Matrix, PRD section 4). If a connector typically alerts 90 seconds after the
triggering event, a 300-second window gives comfortable margin without being
so wide it starts picking up unrelated activity on a busy host.

**Overlapping windows are expected and handled.** Two evidence events on the
same technique/asset within `window_seconds` of each other will have
overlapping query ranges. The matcher (`matcher.candidates_in_window` +
`matcher.best_match`) attributes a candidate SIEM event to whichever evidence
event's timestamp it is closest to — see
`test_overlapping_time_windows_attribute_to_nearest_action` for the exact
behaviour. You do not need to manually shrink windows to avoid overlap.

## 3. Confidence score weights

`confidence.py` computes a weighted score:

```
confidence = 0.55 * field_match_ratio
           + 0.30 * time_proximity_score
           + 0.15 * connector_agreement
```

These weights are module constants (`FIELD_MATCH_WEIGHT`,
`TIME_PROXIMITY_WEIGHT`, `CONNECTOR_AGREEMENT_WEIGHT`) rather than a runtime
config file, deliberately: the causal chain and reproducibility guarantee
(PRD section 6) depend on the same rule version + evidence always producing
the same verdict. If you need to change the weights for a tenant or a
detection content pack, treat it as a versioned code change (bump the rule
engine's own version), not a live-tunable setting — otherwise a re-validation
run months later could silently produce a different verdict for the same
inputs with no record of why.

If you do need to adjust weights (e.g. after the Week 13 fidelity-tuning
follow-up produces better field-match data), the three constants must always
sum to `1.0`. There's no runtime assertion for this today — add one if you
touch these constants, so a bad edit fails fast in CI rather than silently
producing scores that can exceed 1.0.

### 3.1 Threshold bands (Outcome Classifier)

| Verdict | Confidence range | Configured in |
|---|---|---|
| Detected | ≥ 0.7 | `OutcomeClassifier.THRESHOLDS['detected']` |
| Partial | 0.3 – 0.69 | `OutcomeClassifier.THRESHOLDS['partial']` |
| Missed | < 0.3 | (implicit — anything below `partial`) |
| NoData | N/A | Set when the SIEM connector returned zero results at all, not merely zero matching results |

These are also code constants for the same reproducibility reason as the
confidence weights above.

## 4. Connector concurrency and the query cache

The engine fans out all applicable-rule queries for one evidence event in
parallel (`asyncio.gather`), and additionally validates many evidence events
concurrently via `batch_validate()`. Two settings bound this:

| Setting | Default | Where | Purpose |
|---|---|---|---|
| `max_concurrent_queries` | 8 | `ValidationEngine.__init__` | Semaphore limiting simultaneous in-flight SIEM queries across the whole engine instance. Set this below the lowest per-connector API rate limit in the SIEM Compatibility Matrix (PRD section 4) — e.g. if the tenant only has a QRadar connector at 25 req/s, don't set this so high that a single batch validation run bursts past that. |
| `DEFAULT_CACHE_TTL_SECONDS` | 300 | `ValidationEngine.DEFAULT_CACHE_TTL_SECONDS` | How long a SIEM query result is cached, keyed by `(rule.content_hash, time-bucket)`. Prevents re-querying the SIEM when re-validation runs or overlapping-window evidence events would otherwise repeat an identical query. |

**Cache backend:** pass any object implementing `CacheClient` (`get`/`set`)
to `ValidationEngine(cache=...)`. `InMemoryCache` is provided for local dev
and tests. Production should pass a Redis-backed client with the same
interface — this is a straight swap, no engine code changes required.

**Choosing a TTL:** the cache key already buckets the query time range to
the minute, so TTL mainly controls how long a *duplicate* re-validation
request (same rule, same window) can reuse a result before requiring a fresh
SIEM query. 300s is a reasonable default; shorten it for techniques where the
tenant's SIEM ingests near-real-time and a stale cache could miss a
just-arrived alert during an active re-validation loop.

## 5. Multi-connector validation

When more than one SIEM connector has an applicable rule for a technique
(e.g. Splunk and QRadar both have a T1486 ransomware rule), the engine
queries all of them in parallel and selects the single best-scoring result
(`ValidationEngine.validate`, the `best_result` accumulator). No connector is
treated as authoritative by default — the `connector_agreement` term in the
confidence score rewards (small weight) alerts that multiple connectors
agree on, but a single strong match from one connector can still outscore a
weak match from another.

If your deployment wants to prefer a specific vendor's alert when both fire
(e.g. because one connector is known to be noisier), do this at the rule
level — mark the noisier connector's rule with a lower `level` in its Sigma
metadata and exclude it from ingestion for that technique — rather than
special-casing vendor names in the engine.

## 6. Operational checklist

Before deploying a Validation Engine instance for a new tenant:

- [ ] Confirm `max_concurrent_queries` is below every connected connector's
      documented API rate limit (PRD section 4, Global SIEM Compatibility
      Matrix).
- [ ] Confirm the cache backend is the production Redis client, not
      `InMemoryCache` (which does not enforce TTL and does not survive a
      process restart).
- [ ] For any technique with unusually slow connector alerting, set
      `window_seconds` on the corresponding evidence events rather than
      raising the tenant-wide default (keeps windows tight everywhere else,
      which reduces false cross-attribution risk — section 2 above).
- [ ] Run the edge-case test suite
      (`services/validation_engine/tests/test_engine_edge_cases.py`) against
      the tenant's actual connector fixtures if any custom connector
      behaviour (pagination quirks, timestamp timezone handling) differs
      from the standard five.
- [ ] Do not modify the confidence weight or threshold constants without a
      version bump and a note in the causal chain / rule versioning history —
      see section 3.

## 7. Troubleshooting

| Symptom | Likely cause | Where to look |
|---|---|---|
| Verdict is `NoData` when you expected `Missed` | The connector returned zero results for *any* query in the window, not just zero matches | `engine.py`, `any_results_at_all` |
| Two near-simultaneous actions get identical verdicts when they shouldn't | Both evidence events' windows contain the same alert equidistant in time | Check `matcher.best_match` tie-break (falls back to `event_id`) — this is deterministic but may not be the semantically "right" pick; consider narrowing `window_seconds` for that technique |
| Confidence looks lower than expected for what seems like an exact match | `expected_observable` sub-fields don't literally appear in the connector's normalised OCSF field names | Check the OCSF adapter's field mapping (PRD section 3.5) for that vendor — the field match ratio is a literal substring check against the OCSF field bag |
| Re-validation runs are slow / hitting connector rate limits | Cache TTL too short, or `max_concurrent_queries` too high for the connector | Section 4 above |
