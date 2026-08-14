"""Shared pytest fixtures."""

from __future__ import annotations

from pathlib import Path

import pytest

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"


@pytest.fixture
def insecure_spec() -> Path:
    return EXAMPLES / "petstore-insecure.yaml"


@pytest.fixture
def secure_spec() -> Path:
    return EXAMPLES / "petstore-secure.yaml"
