"""AI-assist layer: prioritize findings and draft narratives.

Deterministic by default (works fully offline, no API key, no data leaves the
machine — important for bug-bounty confidentiality). An LLM can be plugged into
`refine()` later, but the core triage is transparent and reproducible: AI
proposes, deterministic logic ranks, a human confirms.
"""

from apsec.ai.assist import narrative, prioritize

__all__ = ["prioritize", "narrative"]
