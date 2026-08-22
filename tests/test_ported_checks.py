"""Tests de los 5 checks estáticos portados: DATA-001, SSRF-001, INV-002/003/004."""

from __future__ import annotations

from apsec.parsers.openapi import OpenAPIDocument
from apsec.scanner.checks import ALL_CHECKS
from apsec.scanner.checks.data_exposure import SensitiveDataInResponse
from apsec.scanner.checks.inventory import (
    DeprecatedEndpointExposed,
    MissingApiDescription,
    MixedApiVersions,
)
from apsec.scanner.checks.ssrf_surface import SsrfProneParameter
from apsec.scanner.models import Severity


def _doc(paths: dict, **extra) -> OpenAPIDocument:
    raw = {"openapi": "3.0.0", "info": {"title": "T"}, "paths": paths, **extra}
    return OpenAPIDocument(raw=raw, source="test")


def _ids(findings) -> list[str]:
    return [f.check_id for f in findings]


class TestRegistry:
    def test_all_five_registered(self) -> None:
        ids = {c.id for c in ALL_CHECKS}
        assert {"APSEC-DATA-001", "APSEC-SSRF-001",
                "APSEC-INV-002", "APSEC-INV-003", "APSEC-INV-004"} <= ids

    def test_no_duplicate_ids(self) -> None:
        ids = [c.id for c in ALL_CHECKS]
        assert len(ids) == len(set(ids))


class TestDataExposure:
    def test_sensitive_field_flagged(self) -> None:
        doc = _doc({"/u": {"get": {"summary": "x", "responses": {"200": {"content":
            {"application/json": {"schema": {"type": "object", "properties":
                {"id": {"type": "integer"}, "password": {"type": "string"}}}}}}}}}})
        f = list(SensitiveDataInResponse().run(doc))
        assert "APSEC-DATA-001" in _ids(f)
        assert f[0].severity == Severity.HIGH
        assert "password" in f[0].description

    def test_nested_and_array_fields(self) -> None:
        doc = _doc({"/u": {"get": {"responses": {"200": {"content":
            {"application/json": {"schema": {"type": "array", "items":
                {"type": "object", "properties": {"api_key": {"type": "string"}}}}}}}}}}})
        assert "APSEC-DATA-001" in _ids(list(SensitiveDataInResponse().run(doc)))

    def test_clean_response_not_flagged(self) -> None:
        doc = _doc({"/u": {"get": {"responses": {"200": {"content":
            {"application/json": {"schema": {"properties":
                {"id": {"type": "integer"}, "name": {"type": "string"}}}}}}}}}})
        assert list(SensitiveDataInResponse().run(doc)) == []

    def test_non_2xx_ignored(self) -> None:
        doc = _doc({"/u": {"get": {"responses": {"500": {"content":
            {"application/json": {"schema": {"properties":
                {"secret": {"type": "string"}}}}}}}}}})
        assert list(SensitiveDataInResponse().run(doc)) == []


class TestSsrf:
    def test_url_param_flagged(self) -> None:
        doc = _doc({"/hook": {"post": {"parameters":
            [{"name": "callback_url", "in": "query"}], "responses": {}}}})
        f = list(SsrfProneParameter().run(doc))
        assert "APSEC-SSRF-001" in _ids(f)
        assert f[0].severity == Severity.MEDIUM

    def test_webhook_param_flagged(self) -> None:
        doc = _doc({"/h": {"post": {"parameters":
            [{"name": "webhook", "in": "query"}], "responses": {}}}})
        assert "APSEC-SSRF-001" in _ids(list(SsrfProneParameter().run(doc)))

    def test_ordinary_param_not_flagged(self) -> None:
        doc = _doc({"/u": {"get": {"parameters":
            [{"name": "page", "in": "query"}], "responses": {}}}})
        assert list(SsrfProneParameter().run(doc)) == []


class TestInventory:
    def test_deprecated_flagged(self) -> None:
        doc = _doc({"/old": {"get": {"deprecated": True, "responses": {}}}})
        assert "APSEC-INV-002" in _ids(list(DeprecatedEndpointExposed().run(doc)))

    def test_not_deprecated_ok(self) -> None:
        doc = _doc({"/ok": {"get": {"responses": {}}}})
        assert list(DeprecatedEndpointExposed().run(doc)) == []

    def test_mixed_versions_flagged(self) -> None:
        doc = _doc({"/v1/u": {"get": {"responses": {}}},
                    "/v2/u": {"get": {"responses": {}}}})
        f = list(MixedApiVersions().run(doc))
        assert "APSEC-INV-003" in _ids(f)
        assert "v1, v2" in f[0].description

    def test_single_version_ok(self) -> None:
        doc = _doc({"/v1/u": {"get": {"responses": {}}},
                    "/v1/p": {"get": {"responses": {}}}})
        assert list(MixedApiVersions().run(doc)) == []

    def test_undocumented_flagged(self) -> None:
        doc = _doc({"/u": {"get": {"responses": {}}}})  # sin summary ni description
        f = list(MissingApiDescription().run(doc))
        assert "APSEC-INV-004" in _ids(f)
        assert f[0].severity == Severity.INFO

    def test_documented_ok(self) -> None:
        doc = _doc({"/u": {"get": {"summary": "List users", "responses": {}}}})
        assert list(MissingApiDescription().run(doc)) == []


class TestEndToEndEngine:
    def test_engine_runs_all_with_ported(self) -> None:
        from apsec.scanner.engine import ScanEngine

        doc = _doc(
            {"/v1/u/{id}": {"get": {"deprecated": True, "responses": {"200": {"content":
                {"application/json": {"schema": {"properties": {"token": {"type": "string"}}}}}}},
                "parameters": [{"name": "redirect_uri", "in": "query"}]}},
             "/v2/u": {"post": {"responses": {}}}},
        )
        result = ScanEngine().scan(doc)
        found = {f.check_id for f in result.findings}
        assert {"APSEC-DATA-001", "APSEC-SSRF-001",
                "APSEC-INV-002", "APSEC-INV-003", "APSEC-INV-004"} <= found
