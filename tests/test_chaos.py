"""Tests for the chaos engine using MockTransport."""

from __future__ import annotations

import httpx

from apsec.chaos import ChaosEngine
from apsec.scanner.models import Severity


async def test_stack_trace_disclosure_detected():
    def handler(request: httpx.Request) -> httpx.Response:
        # Leak a Python traceback whenever the body/content-type is malformed.
        if request.headers.get("content-type", "").startswith("application/json"):
            return httpx.Response(
                500,
                text='Traceback (most recent call last):\n  File "/app/main.py", line 42, in get',
            )
        return httpx.Response(200, text="ok")
    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    result = await ChaosEngine().scan("http://t/api", client=client)
    await client.aclose()
    ids = {f.check_id for f in result.findings}
    assert "APSEC-CHAOS-001" in ids            # stack trace
    assert "APSEC-CHAOS-002" in ids            # /app/main.py path disclosure
    stack = next(f for f in result.findings if f.check_id == "APSEC-CHAOS-001")
    assert stack.severity == Severity.MEDIUM


async def test_robust_server_no_findings():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(400, text='{"error":"bad request"}', headers={"content-type": "application/json"})
    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    result = await ChaosEngine().scan("http://t/api", client=client)
    await client.aclose()
    assert result.findings == []
