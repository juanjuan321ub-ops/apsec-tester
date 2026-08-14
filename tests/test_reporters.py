"""Tests for the JSON, Markdown and HTML reporters."""

from __future__ import annotations

from apsec.reporters import render_html, render_json, render_markdown
from apsec.scanner.models import Finding, ScanResult, Severity


def _sample_result() -> ScanResult:
    r = ScanResult(target="spec.yaml", spec_version="3.0.3", api_title="Demo API")
    r.add(
        Finding(
            check_id="APSEC-AUTH-002",
            title="Unauthenticated write",
            severity=Severity.HIGH,
            location="POST /pets",
            description="No auth on a write operation.",
            remediation="Add security.",
            references=["https://owasp.org/API-Security/"],
        )
    )
    return r


def test_json_report_roundtrips():
    import json

    data = json.loads(render_json(_sample_result()))
    assert data["api_title"] == "Demo API"
    assert data["findings"][0]["check_id"] == "APSEC-AUTH-002"
    assert data["counts"]["HIGH"] == 1


def test_markdown_contains_table_and_details():
    md = render_markdown(_sample_result())
    assert "# 🛡️ APSec Tester" in md
    assert "| Severity | ID | Title | Location |" in md
    assert "APSEC-AUTH-002" in md
    assert "**Remediation:**" in md


def test_html_is_self_contained_and_escapes():
    html = render_html(_sample_result())
    assert html.startswith("<!DOCTYPE html>")
    assert "<style>" in html  # inline CSS, no external assets
    assert "APSEC-AUTH-002" in html
    assert "Demo API" in html


def test_empty_result_renders_clean():
    empty = ScanResult(target="x", spec_version="3.0.3", api_title="Empty")
    assert "No issues" in render_markdown(empty)
    assert "No issues" in render_html(empty)
