"""Tests for live checks and the live scan engine using httpx MockTransport."""

from __future__ import annotations

import httpx
import pytest

from apsec.core.errors import ScanError
from apsec.scanner.live import LiveScanEngine
from apsec.scanner.live.checks.cors import CorsCheck
from apsec.scanner.live.checks.headers import SecurityHeadersCheck
from apsec.scanner.live.checks.info import InfoDisclosureCheck
from apsec.scanner.live.checks.ratelimit import RateLimitCheck
from apsec.scanner.models import Severity

BASE = "https://api.test"


def _client(handler) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(handler))


def test_missing_security_headers_flagged():
    client = _client(lambda req: httpx.Response(200, headers={}))
    findings = list(SecurityHeadersCheck().run(client, BASE))
    ids = {f.title for f in findings}
    assert any("strict-transport-security" in t for t in ids)
    assert any("content-security-policy" in t for t in ids)


def test_all_headers_present_no_findings():
    headers = {
        "strict-transport-security": "max-age=63072000",
        "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
        "x-content-type-options": "nosniff",
        "referrer-policy": "no-referrer",
    }
    client = _client(lambda req: httpx.Response(200, headers=headers))
    findings = list(SecurityHeadersCheck().run(client, BASE))
    assert findings == []


def test_cors_reflection_with_credentials_is_critical():
    def handler(req):
        origin = req.headers.get("origin", "")
        return httpx.Response(
            200,
            headers={
                "access-control-allow-origin": origin,
                "access-control-allow-credentials": "true",
            },
        )

    findings = list(CorsCheck().run(_client(handler), BASE))
    assert len(findings) == 1
    assert findings[0].severity == Severity.CRITICAL


def test_info_disclosure_flags_versioned_banner():
    client = _client(lambda req: httpx.Response(200, headers={"server": "nginx/1.25.3"}))
    findings = list(InfoDisclosureCheck().run(client, BASE))
    assert findings and findings[0].check_id == "APSEC-INFO-001"


def test_ratelimit_absent_flagged():
    client = _client(lambda req: httpx.Response(200))
    findings = list(RateLimitCheck().run(client, BASE))
    assert findings and findings[0].check_id == "APSEC-RATE-001"


def test_ratelimit_present_not_flagged():
    client = _client(lambda req: httpx.Response(429))
    findings = list(RateLimitCheck().run(client, BASE))
    assert findings == []


def test_engine_quick_skips_ratelimit():
    client = _client(lambda req: httpx.Response(200))
    result = LiveScanEngine(mode="quick").scan(BASE, client=client)
    assert all(f.check_id != "APSEC-RATE-001" for f in result.findings)


def test_engine_full_includes_ratelimit():
    client = _client(lambda req: httpx.Response(200))
    result = LiveScanEngine(mode="full").scan(BASE, client=client)
    assert any(f.check_id == "APSEC-RATE-001" for f in result.findings)


def test_engine_unreachable_target_raises():
    def handler(req):
        raise httpx.ConnectError("boom")

    with pytest.raises(ScanError):
        LiveScanEngine().scan(BASE, client=_client(handler))
