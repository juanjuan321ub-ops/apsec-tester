"""Inventory & configuration checks.

Maps to OWASP API Security Top 10 (2023):
* API9:2023 Improper Inventory Management

Static contract signals: deprecated operations still exposed, multiple major API
versions coexisting in the paths, and operations with no documentation.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

from apsec.parsers.openapi import OpenAPIDocument
from apsec.scanner.checks._helpers import is_deprecated
from apsec.scanner.checks.base import Check
from apsec.scanner.models import Finding, Severity

_REF = (
    "https://owasp.org/API-Security/editions/2023/en/"
    "0xa9-improper-inventory-management/"
)

_VERSION_RE = re.compile(r"/v(\d+)(?:/|$)", re.IGNORECASE)


class DeprecatedEndpointExposed(Check):
    """Operations marked deprecated but still present in the contract."""

    id = "APSEC-INV-002"
    name = "Deprecated endpoint still exposed"

    def run(self, doc: OpenAPIDocument) -> Iterable[Finding]:
        for op in doc.operations():
            if is_deprecated(op):
                yield Finding(
                    check_id=self.id,
                    title="Deprecated endpoint still exposed",
                    severity=Severity.LOW,
                    location=op.label,
                    description=(
                        f"{op.label} is marked deprecated but remains documented. "
                        "Obsolete endpoints often go unpatched and widen the "
                        "attack surface (OWASP API9:2023)."
                    ),
                    remediation=(
                        "Set and communicate a sunset date, then remove the "
                        "endpoint from production once it lapses."
                    ),
                    references=[_REF],
                )


class MixedApiVersions(Check):
    """Multiple major versions coexisting across the paths."""

    id = "APSEC-INV-003"
    name = "Multiple API versions coexisting"

    def run(self, doc: OpenAPIDocument) -> Iterable[Finding]:
        versions: set[str] = set()
        for op in doc.operations():
            m = _VERSION_RE.search(op.path)
            if m:
                versions.add(m.group(1))
        if len(versions) > 1:
            ordered = sorted(versions, key=int)
            yield Finding(
                check_id=self.id,
                title="Multiple API versions coexisting",
                severity=Severity.LOW,
                location="global",
                description=(
                    "Paths mix several major versions "
                    f"(v{', v'.join(ordered)}). Older versions often lack the "
                    "latest security controls (OWASP API9:2023)."
                ),
                remediation=(
                    "Inventory each version, apply the same controls, and retire "
                    "old versions with a sunset policy."
                ),
                references=[_REF],
            )


class MissingApiDescription(Check):
    """Operations with no summary/description: poor documentation."""

    id = "APSEC-INV-004"
    name = "Operation without documentation"

    def run(self, doc: OpenAPIDocument) -> Iterable[Finding]:
        undocumented = [
            op.label for op in doc.operations()
            if not (op.summary or op.raw.get("description"))
        ]
        if undocumented:
            preview = ", ".join(undocumented[:8])
            more = "" if len(undocumented) <= 8 else f" (+{len(undocumented) - 8} more)"
            yield Finding(
                check_id=self.id,
                title="Undocumented operations",
                severity=Severity.INFO,
                location="global",
                description=(
                    f"{len(undocumented)} operation(s) have no summary/description. "
                    "Incomplete documentation hampers inventory and security "
                    f"review (OWASP API9:2023). Examples: {preview}{more}."
                ),
                remediation="Document every operation with a summary and description.",
                references=[_REF],
            )
