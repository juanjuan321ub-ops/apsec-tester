"""Tests for the flow (BOLA/IDOR) engine using a stateful mock API."""

from __future__ import annotations

import json as jsonlib
from pathlib import Path

import httpx

from apsec.flow import FlowEngine, load_flow
from apsec.flow.extract import extract, substitute
from apsec.scanner.models import Severity

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"


def test_extract_and_substitute():
    data = {"id": 42, "items": [{"id": 7}]}
    assert extract(data, "$.id") == 42
    assert extract(data, "$.items[0].id") == 7
    assert extract(data, "$.missing") is None
    assert substitute("/documents/{doc_id}", {"doc_id": 42}) == "/documents/42"


def _mock_api(*, vulnerable: bool):
    """A tiny documents API. If vulnerable, it ignores ownership on GET."""
    store: dict[str, str] = {}
    counter = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        auth = request.headers.get("authorization")
        path = request.url.path
        if request.method == "POST" and path == "/documents":
            if not auth:
                return httpx.Response(401)
            counter["n"] += 1
            doc_id = str(counter["n"])
            store[doc_id] = auth  # owner = token
            return httpx.Response(201, json={"id": int(doc_id)})
        if request.method == "GET" and path.startswith("/documents/"):
            doc_id = path.rsplit("/", 1)[-1]
            if doc_id not in store:
                return httpx.Response(404)
            if not auth:
                return httpx.Response(401)          # unauth always denied here
            if vulnerable or store[doc_id] == auth:
                return httpx.Response(200, json={"id": int(doc_id), "secret": "x"})
            return httpx.Response(403)              # proper ownership check
        return httpx.Response(404)

    return httpx.MockTransport(handler)


async def _run(vulnerable: bool):
    flow = load_flow(EXAMPLES / "flow-bola.yaml")
    client = httpx.AsyncClient(transport=_mock_api(vulnerable=vulnerable))
    result = await FlowEngine(flow).run(client=client)
    await client.aclose()
    return result


async def test_bola_detected_when_api_is_vulnerable():
    result = await _run(vulnerable=True)
    ids = {f.check_id for f in result.findings}
    assert "APSEC-BOLA-001" in ids
    bola = next(f for f in result.findings if f.check_id == "APSEC-BOLA-001")
    assert bola.severity == Severity.CRITICAL
    assert "bob" in bola.location


async def test_no_bola_when_api_enforces_ownership():
    result = await _run(vulnerable=False)
    ids = {f.check_id for f in result.findings}
    assert "APSEC-BOLA-001" not in ids   # bob gets 403
    assert "APSEC-AUTH-010" not in ids    # unauth gets 401


def _mock_bfla(*, vulnerable: bool):
    def handler(request: httpx.Request) -> httpx.Response:
        auth = request.headers.get("authorization", "")
        if request.url.path == "/admin/promote":
            if vulnerable or auth == "Bearer admin-token":
                return httpx.Response(200, json={"ok": True})
            return httpx.Response(403)
        return httpx.Response(404)
    return httpx.MockTransport(handler)


def _bfla_flow():
    from apsec.flow.models import Flow, Identity, Step
    return Flow(
        name="admin function",
        base_url="http://t",
        identities={
            "admin": Identity("admin", {"Authorization": "Bearer admin-token"}),
            "bob": Identity("bob", {"Authorization": "Bearer bob-token"}),
        },
        steps=[Step(id="promote", identity="admin", method="POST", path="/admin/promote",
                    abuse=["bfla"])],
    )


async def test_bfla_detected_when_vulnerable():
    client = httpx.AsyncClient(transport=_mock_bfla(vulnerable=True))
    result = await FlowEngine(_bfla_flow()).run(client=client)
    await client.aclose()
    assert "APSEC-BFLA-001" in {f.check_id for f in result.findings}


async def test_bfla_absent_when_enforced():
    client = httpx.AsyncClient(transport=_mock_bfla(vulnerable=False))
    result = await FlowEngine(_bfla_flow()).run(client=client)
    await client.aclose()
    assert "APSEC-BFLA-001" not in {f.check_id for f in result.findings}


def _mass_flow():
    from apsec.flow.models import Flow, Identity, Step
    return Flow(
        name="mass assignment",
        base_url="http://t",
        identities={"alice": Identity("alice", {"Authorization": "Bearer a"})},
        steps=[Step(id="create", identity="alice", method="POST", path="/users",
                    json_body={"name": "x"}, abuse=["mass_assignment"],
                    mass_assign={"role": "admin"})],
    )


async def test_mass_assignment_detected_when_reflected():
    def handler(request: httpx.Request) -> httpx.Response:
        import json as j
        body = j.loads(request.content or b"{}")
        return httpx.Response(201, json={"id": 1, **body})  # echoes everything -> vulnerable
    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    result = await FlowEngine(_mass_flow()).run(client=client)
    await client.aclose()
    mass = [f for f in result.findings if f.check_id == "APSEC-MASS-001"]
    assert mass and mass[0].severity == Severity.HIGH


async def test_mass_assignment_absent_when_stripped():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(201, json={"id": 1, "name": "x"})  # ignores role -> safe
    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    result = await FlowEngine(_mass_flow()).run(client=client)
    await client.aclose()
    assert "APSEC-MASS-001" not in {f.check_id for f in result.findings}
