"""Postman Collection (v2.1) loader.

We only need enough of the schema to recover endpoints (method + URL) so they
can be fed to the live prober. Variables like ``{{baseUrl}}`` are resolved from
the collection's own ``variable`` block when present.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from apsec.core.errors import SpecLoadError
from apsec.core.logger import get_logger

log = get_logger("apsec.parsers.postman")

_VAR_RE = re.compile(r"\{\{(\w+)\}\}")


@dataclass(frozen=True)
class Endpoint:
    method: str
    url: str

    @property
    def label(self) -> str:
        return f"{self.method.upper()} {self.url}"


@dataclass
class PostmanCollection:
    name: str
    endpoints: list[Endpoint] = field(default_factory=list)
    variables: dict[str, str] = field(default_factory=dict)

    @property
    def base_url(self) -> str | None:
        """Best-effort base URL derived from the first absolute endpoint."""
        for ep in self.endpoints:
            parts = urlsplit(ep.url)
            if parts.scheme and parts.netloc:
                return f"{parts.scheme}://{parts.netloc}"
        return None


def _resolve_vars(text: str, variables: dict[str, str]) -> str:
    return _VAR_RE.sub(lambda m: variables.get(m.group(1), m.group(0)), text)


def _extract_url(url_field: Any, variables: dict[str, str]) -> str:
    if isinstance(url_field, str):
        raw = url_field
    elif isinstance(url_field, dict):
        raw = url_field.get("raw", "")
    else:
        raw = ""
    return _resolve_vars(str(raw), variables)


def _walk_items(items: list[Any], variables: dict[str, str], out: list[Endpoint]) -> None:
    for item in items:
        if not isinstance(item, dict):
            continue
        if "item" in item and isinstance(item["item"], list):
            _walk_items(item["item"], variables, out)  # folder
            continue
        request = item.get("request")
        if isinstance(request, dict):
            method = str(request.get("method", "GET")).upper()
            url = _extract_url(request.get("url"), variables)
            if url:
                out.append(Endpoint(method=method, url=url))


def load_postman(path: str | Path) -> PostmanCollection:
    """Load a Postman v2.x collection and extract its endpoints."""
    p = Path(path)
    try:
        text = p.read_text(encoding="utf-8")
    except OSError as exc:
        raise SpecLoadError(f"Could not read Postman collection {p}: {exc}") from exc

    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise SpecLoadError(f"Invalid JSON in Postman collection {p}: {exc}") from exc

    if not isinstance(data, dict) or "item" not in data:
        raise SpecLoadError(f"{p}: not a recognizable Postman collection (missing 'item')")

    variables = {
        str(v.get("key")): str(v.get("value", ""))
        for v in (data.get("variable") or [])
        if isinstance(v, dict) and v.get("key")
    }
    name = str(data.get("info", {}).get("name", "Postman Collection"))

    endpoints: list[Endpoint] = []
    _walk_items(data.get("item", []), variables, endpoints)
    log.debug("Loaded %d endpoint(s) from %s", len(endpoints), p)
    return PostmanCollection(name=name, endpoints=endpoints, variables=variables)
