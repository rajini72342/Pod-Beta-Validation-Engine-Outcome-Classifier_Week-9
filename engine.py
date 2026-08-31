"""Validation Engine core (PRD section 3.3), optimized per Week 11 code review.

Key changes vs. the Week 4 skeleton:
  * Applicable rules for a given evidence event are queried in parallel
    (asyncio.gather), bounded by a per-tenant semaphore, instead of a
    sequential for-loop.
  * SIEM query results are cached (rule content_hash + time-bucket key) to
    avoid re-querying on overlapping/duplicate validation runs.
  * Confidence scoring is delegated to confidence.compute_confidence, fed by
    matcher.candidates_in_window / matcher.best_match rather than an
    unspecified "results" match.
  * batch_validate() processes many evidence events concurrently, which is
    what the Week 7 load-testing scope (1000+ events) exercises.
"""
from __future__ import annotations

import asyncio
import hashlib
from typing import Iterable, Optional, Protocol

from .confidence import compute_confidence
from .matcher import applicable_rules, best_match, candidates_in_window, evidence_window
from .models import DetectionRule, EvidenceEvent, RawValidationResult, SiemMatchEvent


class ConnectorLike(Protocol):
    vendor: str

    async def query(self, query_str: str, time_range: tuple) -> list[dict]: ...


class CacheClient(Protocol):
    async def get(self, key: str) -> Optional[list[dict]]: ...
    async def set(self, key: str, value: list[dict], ttl_seconds: int) -> None: ...


class InMemoryCache:
    """Trivial cache used in tests / local dev when Redis isn't wired up.
    Same shape as the real Redis-backed client so swapping is a one-line change.
    """

    def __init__(self) -> None:
        self._store: dict[str, list[dict]] = {}

    async def get(self, key: str) -> Optional[list[dict]]:
        return self._store.get(key)

    async def set(self, key: str, value: list[dict], ttl_seconds: int) -> None:
        # TTL not enforced in-memory; production Redis client sets EX=ttl_seconds.
        self._store[key] = value


def _cache_key(rule: DetectionRule, time_range: tuple) -> str:
    # Bucket the time range to the minute so near-identical re-validation runs
    # (e.g. re-run within the same window) hit the cache.
    bucket_start = time_range[0].replace(second=0, microsecond=0).isoformat()
    bucket_end = time_range[1].replace(second=0, microsecond=0).isoformat()
    raw = f"{rule.content_hash}:{bucket_start}:{bucket_end}"
    return hashlib.sha256(raw.encode()).hexdigest()


class ValidationEngine:
    DEFAULT_CACHE_TTL_SECONDS = 300

    def __init__(
        self,
        connector_registry: dict[str, ConnectorLike],
        cache: Optional[CacheClient] = None,
        max_concurrent_queries: int = 8,
    ) -> None:
        self.registry = connector_registry
        self.cache = cache or InMemoryCache()
        self._sem = asyncio.Semaphore(max_concurrent_queries)

    async def _query_rule(
        self, rule: DetectionRule, time_range: tuple
    ) -> list[SiemMatchEvent]:
        connector = self.registry.get(rule.vendor)
        if connector is None:
            return []

        key = _cache_key(rule, time_range)
        cached = await self.cache.get(key)
        if cached is not None:
            raw = cached
        else:
            async with self._sem:
                raw = await connector.query(rule.query_str, time_range)
            await self.cache.set(key, raw, self.DEFAULT_CACHE_TTL_SECONDS)

        return [SiemMatchEvent(**item) for item in raw]

    async def validate(
        self, evidence: EvidenceEvent, rules: Iterable[DetectionRule]
    ) -> RawValidationResult:
        rules = applicable_rules(evidence, rules)
        if not rules:
            return RawValidationResult(
                action_id=evidence.action_id,
                rule_id="NONE",
                technique_ref=evidence.technique_ref,
                confidence=0.0,
                no_data=True,
                causal_chain=[
                    f"No detection rules registered for technique {evidence.technique_ref}"
                ],
            )

        time_range = evidence_window(evidence)
        vendors = [r.vendor for r in rules]

        # Fan out all applicable rule queries in parallel instead of the
        # Week 4 sequential loop.
        query_results = await asyncio.gather(
            *(self._query_rule(rule, time_range) for rule in rules)
        )

        any_results_at_all = any(len(r) > 0 for r in query_results)

        best_result: Optional[RawValidationResult] = None
        for rule, raw_events in zip(rules, query_results):
            candidates = candidates_in_window(evidence, raw_events)
            match = best_match(evidence, candidates)
            confidence = compute_confidence(evidence, match, vendors)

            chain = [f"Evidence event received: {evidence.action_id}", f"Rule executed: {rule.rule_id} ({rule.vendor})"]
            mttd = None
            if match is not None:
                mttd = abs((match.timestamp - evidence.timestamp).total_seconds())
                chain.append(
                    f"Matched SIEM event {match.event_id} within window "
                    f"({mttd:.1f}s from attack timestamp)"
                )
            else:
                chain.append("No SIEM event in evidence window matched expected observable")

            result = RawValidationResult(
                action_id=evidence.action_id,
                rule_id=rule.rule_id,
                technique_ref=evidence.technique_ref,
                confidence=confidence,
                matched_events=[match] if match else [],
                no_data=not any_results_at_all,
                causal_chain=chain,
                mttd_seconds=mttd,
            )

            if best_result is None or result.confidence > best_result.confidence:
                best_result = result

        assert best_result is not None  # rules is non-empty, loop always runs at least once
        return best_result

    async def batch_validate(
        self, evidence_events: Iterable[EvidenceEvent], rules: list[DetectionRule]
    ) -> list[RawValidationResult]:
        """Validate many evidence events concurrently. Used by the Week 7
        load-testing scope and by day-to-day campaign validation runs.
        """
        return await asyncio.gather(
            *(self.validate(evidence, rules) for evidence in evidence_events)
        )
