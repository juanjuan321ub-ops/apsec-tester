"""Tests for the Postman collection parser."""

from __future__ import annotations

from pathlib import Path

from apsec.parsers.postman import load_postman

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"


def test_loads_endpoints_and_resolves_variables():
    coll = load_postman(EXAMPLES / "collection.postman.json")
    labels = {ep.label for ep in coll.endpoints}
    assert "GET https://api.demo.example.com/health" in labels
    assert "POST https://api.demo.example.com/users" in labels  # nested folder
    assert coll.base_url == "https://api.demo.example.com"
