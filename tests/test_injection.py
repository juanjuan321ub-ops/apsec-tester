"""Tests for the injection engine (SQLi + reflected XSS) via MockTransport."""

from __future__ import annotations

import httpx

from apsec.scanner.injection import InjectionEngine


async def test_sqli_detected_on_error_signature():
    def handler(request: httpx.Request) -> httpx.Response:
        # httpx decodes params, so a URL-encoded %27 comes back as a quote.
        val = request.url.params.get("id", "")
        if "'" in val or '"' in val:
            return httpx.Response(500, text="You have an error in your SQL syntax; MySQL")
        return httpx.Response(200, text="ok")
    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    result = await InjectionEngine().scan(["http://t/api?id=1"], client=client)
    await client.aclose()
    assert "APSEC-SQLI-001" in {f.check_id for f in result.findings}


async def test_reflected_xss_detected():
    def handler(request: httpx.Request) -> httpx.Response:
        q = str(request.url.query)
        body = f"<html>search: {request.url.params.get('q','')}</html>"
        return httpx.Response(200, text=body, headers={"content-type": "text/html"})
    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    result = await InjectionEngine().scan(["http://t/search?q=hi"], client=client)
    await client.aclose()
    assert "APSEC-XSS-001" in {f.check_id for f in result.findings}


async def test_clean_endpoint_no_findings():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="all good", headers={"content-type": "application/json"})
    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    result = await InjectionEngine().scan(["http://t/api?id=1"], client=client)
    await client.aclose()
    assert result.findings == []


async def test_out_of_scope_url_skipped():
    from apsec.core.scope import Scope
    def handler(request):
        return httpx.Response(500, text="SQL syntax error MySQL")
    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    scope = Scope(include=["*.example.com"])
    result = await InjectionEngine(scope=scope).scan(["http://evil.com/api?id=1"], client=client)
    await client.aclose()
    assert result.findings == []
