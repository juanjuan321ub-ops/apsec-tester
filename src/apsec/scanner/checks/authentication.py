"""Authentication & authorization contract checks.

These map to OWASP API Security Top 10 (2023):
* API2:2023 Broken Authentication
* API5:2023 Broken Function Level Authorization
"""

from __future__ import annotations

from collections.abc import Iterable

from apsec.parsers.openapi import OpenAPIDocument
from apsec.scanner.checks.base import Check
from apsec.scanner.models import Finding, Severity

_OWASP_AUTH = "https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/"


class GlobalSecurityCheck(Check):
    """Flag specs that declare no global security requirement at all."""

    id = "APSEC-AUTH-001"
    name = "Global security requirement present"

    def run(self, doc: OpenAPIDocument) -> Iterable[Finding]:
        if not doc.security_schemes:
            yield Finding(
                check_id=self.id,
                title="No security schemes defined",
                severity=Severity.HIGH,
                location="components.securitySchemes",
                description=(
                    "The specification declares no securitySchemes. An API with "
                    "no documented authentication mechanism is either fully "
                    "public or under-documented — both are risks."
                ),
                remediation=(
                    "Define at least one scheme under components.securitySchemes "
                    "(e.g. OAuth2, HTTP bearer/JWT) and reference it."
                ),
                references=[_OWASP_AUTH],
            )
            return

        if not doc.global_security:
            yield Finding(
                check_id=self.id,
                title="No global 'security' applied",
                severity=Severity.MEDIUM,
                location="global",
                description=(
                    "Security schemes exist but no top-level 'security' is set, "
                    "so protection depends entirely on per-operation overrides. "
                    "A single missing override silently exposes an endpoint."
                ),
                remediation=(
                    "Apply a default 'security' at the document root and relax it "
                    "only on the specific operations meant to be public."
                ),
                references=[_OWASP_AUTH],
            )


class OperationSecurityCheck(Check):
    """Flag write operations that opt out of authentication."""

    id = "APSEC-AUTH-002"
    name = "Write operations require authentication"

    _WRITE_METHODS = {"post", "put", "patch", "delete"}

    def run(self, doc: OpenAPIDocument) -> Iterable[Finding]:
        has_global = bool(doc.global_security)
        for op in doc.operations():
            # An explicit empty list (`security: []`) disables auth for this op.
            explicitly_public = op.security == []
            inherits_protection = has_global and op.security is None
            protected = inherits_protection or (op.security not in (None, []))

            if op.method in self._WRITE_METHODS and (explicitly_public or not protected):
                yield Finding(
                    check_id=self.id,
                    title="State-changing operation is unauthenticated",
                    severity=Severity.HIGH,
                    location=op.label,
                    description=(
                        f"{op.label} changes state but has no effective security "
                        "requirement. Unauthenticated writes are a common path to "
                        "data tampering and abuse."
                    ),
                    remediation=(
                        "Attach a 'security' requirement to this operation, or "
                        "confirm and document why it must be public."
                    ),
                    references=[_OWASP_AUTH],
                )


class WeakSecuritySchemeCheck(Check):
    """Flag security schemes known to be weak in transit."""

    id = "APSEC-AUTH-003"
    name = "No weak/basic auth schemes"

    def run(self, doc: OpenAPIDocument) -> Iterable[Finding]:
        for name, scheme in doc.security_schemes.items():
            if not isinstance(scheme, dict):
                continue
            stype = str(scheme.get("type", "")).lower()
            sub = str(scheme.get("scheme", "")).lower()

            if stype == "http" and sub == "basic":
                yield Finding(
                    check_id=self.id,
                    title=f"HTTP Basic auth scheme '{name}'",
                    severity=Severity.MEDIUM,
                    location=f"components.securitySchemes.{name}",
                    description=(
                        "HTTP Basic transmits base64-encoded credentials on every "
                        "request. Without strict TLS it is trivially decodable and "
                        "offers no token rotation or scoping."
                    ),
                    remediation=(
                        "Prefer short-lived bearer tokens (OAuth2/JWT). If Basic is "
                        "unavoidable, enforce TLS and rotate credentials."
                    ),
                    references=[_OWASP_AUTH],
                )
            elif stype == "apikey" and str(scheme.get("in", "")).lower() == "query":
                yield Finding(
                    check_id=self.id,
                    title=f"API key in query string ('{name}')",
                    severity=Severity.MEDIUM,
                    location=f"components.securitySchemes.{name}",
                    description=(
                        "API keys passed as query parameters leak into server "
                        "logs, browser history and referer headers."
                    ),
                    remediation="Send API keys in a header, not the query string.",
                    references=[_OWASP_AUTH],
                )
