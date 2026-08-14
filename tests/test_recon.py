"""Tests for the recon engine using mocked CT source, resolver and HTTP."""

from __future__ import annotations

import httpx
import pytest

from apsec.core.errors import ScanError
from apsec.core.scope import Scope
from apsec.recon import ReconEngine


@pytest.mark.asyncio
async def test_recon_discovers_filters_and_probes():
    scope = Scope(include=["*.example.com"], exclude=["secret.example.com"])

    async def fake_source(client, domain):
        # crt.sh-like output including an out-of-scope and an excluded host.
        return {
            "api.example.com",
            "www.example.com",
            "secret.example.com",   # excluded -> must be dropped
            "evil.com",             # out of scope -> must be dropped
        }

    async def fake_resolver(host):
        return ["93.184.216.34"] if host != "www.example.com" else []

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, headers={"server": "nginx"}, text="<title>API</title>")

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    engine = ReconEngine(scope, sources=(fake_source,), resolver=fake_resolver)
    assets = await engine.run(client=client)
    await client.aclose()

    hosts = {a.host for a in assets}
    assert "api.example.com" in hosts
    assert "secret.example.com" not in hosts   # excluded
    assert "evil.com" not in hosts             # out of scope
    assert "www.example.com" not in hosts      # unresolved -> dropped

    api = next(a for a in assets if a.host == "api.example.com")
    assert api.alive and api.status == 200 and api.title == "API"


def test_recon_refuses_empty_scope():
    with pytest.raises(ScanError):
        ReconEngine(Scope(include=[]))
