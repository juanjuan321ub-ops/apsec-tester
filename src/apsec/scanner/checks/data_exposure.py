"""Excessive data exposure — sensitive fields in response schemas.

Maps to OWASP API Security Top 10 (2023):
* API3:2023 Broken Object Property Level Authorization

Walks the response schemas and flags properties whose name suggests sensitive
data (passwords, tokens, financial PII). Works on the de-referenced spec; does
not fetch remote $refs (SSRF-safe, per the loader's design).
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from apsec.parsers.openapi import OpenAPIDocument
from apsec.scanner.checks._helpers import op_responses
from apsec.scanner.checks.base import Check
from apsec.scanner.models import Finding, Severity

_REF = (
    "https://owasp.org/API-Security/editions/2023/en/"
    "0xa3-broken-object-property-level-authorization/"
)

# Nombres que sugieren un dato que no debería serializarse al cliente.
SENSITIVE_FIELD_KEYWORDS = (
    "password", "passwd", "pwd", "secret", "token", "apikey", "api_key",
    "private_key", "privatekey", "ssn", "creditcard", "credit_card", "cvv",
    "card_number", "pin", "salt", "hash",
)

_MAX_DEPTH = 15


def _iter_property_names(schema: Any, _depth: int = 0) -> Iterable[str]:
    """Yield property names from a JSON Schema (bounded recursion)."""
    if _depth > _MAX_DEPTH or not isinstance(schema, dict):
        return
    props = schema.get("properties")
    if isinstance(props, dict):
        for name, subschema in props.items():
            yield name
            yield from _iter_property_names(subschema, _depth + 1)
    items = schema.get("items")
    if isinstance(items, dict):
        yield from _iter_property_names(items, _depth + 1)
    for key in ("allOf", "anyOf", "oneOf"):
        for sub in schema.get(key, []) or []:
            yield from _iter_property_names(sub, _depth + 1)


class SensitiveDataInResponse(Check):
    """Sensitive-looking fields present in 2xx response schemas."""

    id = "APSEC-DATA-001"
    name = "Sensitive data exposed in response"

    def run(self, doc: OpenAPIDocument) -> Iterable[Finding]:
        for op in doc.operations():
            flagged: set[str] = set()
            for status, response in op_responses(op).items():
                if not str(status).startswith("2") or not isinstance(response, dict):
                    continue
                for media in (response.get("content") or {}).values():
                    if not isinstance(media, dict):
                        continue
                    for prop in _iter_property_names(media.get("schema", {})):
                        low = prop.lower()
                        if any(kw in low for kw in SENSITIVE_FIELD_KEYWORDS):
                            flagged.add(prop)

            for prop in sorted(flagged):
                yield Finding(
                    check_id=self.id,
                    title="Sensitive field in response schema",
                    severity=Severity.HIGH,
                    location=op.label,
                    description=(
                        f"The response of {op.label} includes the field '{prop}', "
                        "whose name suggests sensitive data that should not be "
                        "returned to the client (OWASP API3:2023)."
                    ),
                    remediation=(
                        "Remove the field from the output DTO or apply "
                        "property-level authorization. Never serialize secrets or "
                        "unnecessary PII."
                    ),
                    references=[_REF],
                )
