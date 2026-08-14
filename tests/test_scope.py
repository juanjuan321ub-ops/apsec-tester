"""Tests for the scope allow-list — the safety core."""

from __future__ import annotations

from pathlib import Path

import pytest

from apsec.core.errors import SpecLoadError
from apsec.core.scope import OutOfScopeError, Scope, load_scope

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"


def test_wildcard_matches_subdomain_not_apex():
    s = Scope(include=["*.example.com"])
    assert s.is_in_scope("api.example.com")
    assert s.is_in_scope("https://api.example.com/x")
    assert not s.is_in_scope("example.com")  # apex needs explicit listing


def test_exclude_wins_over_include():
    s = Scope(include=["*.example.com"], exclude=["blog.example.com"])
    assert s.is_in_scope("api.example.com")
    assert not s.is_in_scope("blog.example.com")


def test_out_of_scope_host_rejected():
    s = Scope(include=["*.example.com"])
    assert not s.is_in_scope("evil.com")
    assert not s.is_in_scope("https://notexample.com")


def test_assert_in_scope_raises():
    s = Scope(include=["*.example.com"])
    with pytest.raises(OutOfScopeError):
        s.assert_in_scope("https://evil.com")


def test_seeds_and_concrete_hosts():
    s = Scope(include=["*.example.com", "api.example.org"])
    assert set(s.seeds()) == {"example.com", "api.example.org"}
    assert s.concrete_hosts() == ["api.example.org"]


def test_load_scope_from_example_file():
    s = load_scope(EXAMPLES / "scope.example.yaml")
    assert s.is_in_scope("api.example.com")
    assert not s.is_in_scope("blog.example.com")  # excluded


def test_empty_include_is_rejected(tmp_path):
    f = tmp_path / "scope.yaml"
    f.write_text("include: []\n", encoding="utf-8")
    with pytest.raises(SpecLoadError):
        load_scope(f)
