"""Recon data types."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class Asset:
    """A discovered host and what we learned about it."""

    host: str
    addresses: list[str] = field(default_factory=list)
    alive: bool = False
    scheme: str | None = None
    status: int | None = None
    title: str | None = None
    server: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
