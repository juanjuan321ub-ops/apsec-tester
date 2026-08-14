"""Tests for the deterministic AI triage layer."""

from __future__ import annotations

from apsec.ai import narrative, prioritize
from apsec.scanner.models import Finding, ScanResult, Severity


def _data():
    r = ScanResult(target="http://t", spec_version="", api_title="Demo")
    r.add(Finding("APSEC-HDR-001", "Missing header", Severity.MEDIUM, "hdr", "d", "fix"))
    r.add(Finding("APSEC-BOLA-001", "IDOR", Severity.CRITICAL, "GET /x", "d", "fix"))
    r.add(Finding("APSEC-INFO-001", "Banner", Severity.LOW, "srv", "d", "fix"))
    return r.to_dict()


def test_bola_ranks_above_header():
    ranked = prioritize(_data())
    assert ranked[0].check_id == "APSEC-BOLA-001"
    ids = [r.check_id for r in ranked]
    assert ids.index("APSEC-BOLA-001") < ids.index("APSEC-HDR-001")


def test_narrative_mentions_top_finding():
    text = narrative(_data())
    assert "APSEC-BOLA-001" in text
    assert "critical" in text.lower()


def test_empty_narrative():
    assert "No findings" in narrative({"findings": [], "counts": {}})
