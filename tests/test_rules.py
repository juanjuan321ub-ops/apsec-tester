"""Tests for custom YAML rules."""

from __future__ import annotations

from pathlib import Path

import httpx

from apsec.scanner.live.rules import load_rules, run_custom_rules

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"


def _client(handler) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(handler))


def test_load_rules_from_yaml():
    rules = load_rules(EXAMPLES / "custom-rules.yaml")
    ids = {r.id for r in rules}
    assert "CUSTOM-HEALTH-001" in ids
    assert "CUSTOM-REQID-001" in ids


def test_rule_fails_when_header_absent():
    rules = load_rules(EXAMPLES / "custom-rules.yaml")
    # No x-request-id header -> CUSTOM-REQID-001 should fail.
    client = _client(lambda req: httpx.Response(200))
    findings = list(run_custom_rules(client, "https://api.test", rules))
    assert any(f.check_id == "CUSTOM-REQID-001" for f in findings)


def test_rule_passes_when_expectations_met():
    rules = load_rules(EXAMPLES / "custom-rules.yaml")

    def handler(req):
        # Satisfy both rules: 200 + x-request-id present, no x-build-version.
        return httpx.Response(200, headers={"x-request-id": "abc123"})

    findings = list(run_custom_rules(_client(handler), "https://api.test", rules))
    assert findings == []
