"""Tests for the scan engine and checks."""

from __future__ import annotations

from apsec.parsers.openapi import load_openapi
from apsec.scanner import ScanEngine, Severity


def _ids(result):
    return {f.check_id for f in result.findings}


def test_insecure_spec_flags_expected_checks(insecure_spec):
    result = ScanEngine().scan(load_openapi(insecure_spec))
    ids = _ids(result)
    assert "APSEC-AUTH-001" in ids   # no global security
    assert "APSEC-AUTH-002" in ids   # unauthenticated writes
    assert "APSEC-AUTH-003" in ids   # basic auth / apikey in query
    assert "APSEC-TLS-001" in ids    # http server
    assert result.highest_severity >= Severity.HIGH


def test_secure_spec_is_clean_of_high(secure_spec):
    result = ScanEngine().scan(load_openapi(secure_spec))
    highs = [f for f in result.findings if f.severity >= Severity.HIGH]
    assert highs == []


def test_unauthenticated_write_located_correctly(insecure_spec):
    result = ScanEngine().scan(load_openapi(insecure_spec))
    auth2 = [f for f in result.findings if f.check_id == "APSEC-AUTH-002"]
    locations = {f.location for f in auth2}
    assert "POST /pets" in locations
    assert "DELETE /pets/{petId}" in locations


def test_result_serializes_to_dict(insecure_spec):
    result = ScanEngine().scan(load_openapi(insecure_spec))
    data = result.to_dict()
    assert "findings" in data and "counts" in data
    assert isinstance(data["findings"], list)
