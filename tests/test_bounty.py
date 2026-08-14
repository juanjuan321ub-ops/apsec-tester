"""Tests for the bounty-ready reporter."""

from __future__ import annotations

from apsec.reporters.bounty_reporter import render_bounty, write_bounty
from apsec.scanner.models import Finding, ScanResult, Severity


def _result():
    r = ScanResult(target="http://t", spec_version="", api_title="Demo")
    r.add(Finding(check_id="APSEC-BOLA-001", title="IDOR", severity=Severity.CRITICAL,
                  location="GET /docs/1 as bob", description="bob read alice's doc.",
                  remediation="Enforce ownership.", references=["https://owasp.org/x"]))
    return r


def test_render_bounty_has_sections():
    md = render_bounty(_result().to_dict())
    for section in ("### Summary", "### Steps to Reproduce", "### Impact", "### Remediation", "CVSS"):
        assert section in md
    assert "APSEC-BOLA-001" in md


def test_write_bounty_roundtrip(tmp_path):
    out = write_bounty(_result(), tmp_path / "b.md")
    assert out.exists() and "IDOR" in out.read_text(encoding="utf-8")
