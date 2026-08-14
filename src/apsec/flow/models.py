"""Data types for declarative abuse-case flows."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class Identity:
    """A caller identity — a named bundle of auth headers."""

    name: str
    headers: dict[str, str] = field(default_factory=dict)


@dataclass
class Step:
    """One request in a flow.

    ``capture`` pulls values out of the JSON response (e.g. a resource id) into
    the flow context so later steps and abuse cases can reference them via
    ``{var}`` placeholders. ``abuse`` lists which abuse cases to derive:

    * ``bola``            replay as other identities (object access)  -> API1
    * ``bfla``            replay as other identities (function access) -> API5
    * ``unauth``          replay with no credentials                   -> API2
    * ``mass_assignment`` resend body with ``mass_assign`` extra fields -> API3/6
    """

    id: str
    identity: str | None
    method: str
    path: str
    json_body: Any | None = None
    headers: dict[str, str] = field(default_factory=dict)
    capture: dict[str, str] = field(default_factory=dict)
    expect_status: int | None = None
    abuse: list[str] = field(default_factory=list)
    mass_assign: dict[str, Any] = field(default_factory=dict)


@dataclass
class Flow:
    """An ordered flow plus the identities available to it."""

    name: str
    steps: list[Step]
    identities: dict[str, Identity] = field(default_factory=dict)
    base_url: str | None = None
