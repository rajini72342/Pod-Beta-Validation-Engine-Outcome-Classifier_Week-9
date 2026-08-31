"""Builds the human/audit-readable causal chain from a RawValidationResult.

Kept as a separate module (rather than inline in classifier.py) so it can be
unit-tested independently and so the step numbering logic doesn't get
tangled with threshold logic.
"""
from __future__ import annotations

from .models import CausalStep


def build_causal_chain(result: dict) -> list[CausalStep]:
    raw_steps: list[str] = result.get("causal_chain", [])
    steps = [
        CausalStep(step_number=i + 1, description=desc)
        for i, desc in enumerate(raw_steps)
    ]
    if not steps:
        # Defensive fallback: never return an empty chain, since auditors rely
        # on there being at least one explanatory step (PRD section 1, honesty
        # over optimism).
        steps = [
            CausalStep(
                step_number=1,
                description=f"Evidence event received: {result.get('action_id', 'unknown')}",
            )
        ]
    return steps
