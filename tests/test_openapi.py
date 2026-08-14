"""Tests for the OpenAPI parser."""

from __future__ import annotations

import pytest

from apsec.core.errors import SpecLoadError, SpecValidationError
from apsec.parsers.openapi import load_openapi


def test_loads_valid_spec(insecure_spec):
    doc = load_openapi(insecure_spec)
    assert doc.version.startswith("3.")
    assert doc.title == "Insecure Petstore (demo target)"
    assert doc.servers == ["http://api.petstore.example.com/v1"]


def test_operations_flatten(insecure_spec):
    doc = load_openapi(insecure_spec)
    labels = {op.label for op in doc.operations()}
    assert "GET /pets" in labels
    assert "POST /pets" in labels
    assert "DELETE /pets/{petId}" in labels


def test_missing_file_raises(tmp_path):
    with pytest.raises(SpecLoadError):
        load_openapi(tmp_path / "does-not-exist.yaml")


def test_bad_version_raises(tmp_path):
    bad = tmp_path / "swagger2.json"
    bad.write_text('{"swagger": "2.0", "paths": {}}', encoding="utf-8")
    with pytest.raises(SpecValidationError):
        load_openapi(bad)


def test_non_mapping_root_raises(tmp_path):
    bad = tmp_path / "list.json"
    bad.write_text("[1, 2, 3]", encoding="utf-8")
    with pytest.raises(SpecLoadError):
        load_openapi(bad)
