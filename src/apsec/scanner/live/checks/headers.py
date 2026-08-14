"""Security header checks (OWASP API8: Security Misconfiguration)."""

from __future__ import annotations

from collections.abc import Iterable

import httpx

from apsec.scanner.live.checks.base import LiveCheck
from apsec.scanner.models import Finding, Severity

_OWASP_MISCONFIG = (
    "https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/"
)

# header -> (severity, human explanation, remediation)
_EXPECTED = {
    "strict-transport-security": (
        Severity.HIGH,
        "HSTS is not set, so browsers may fall back to plaintext HTTP and are "
        "exposed to SSL-stripping downgrade attacks.",
        "Add 'Strict-Transport-Security: max-age=63072000; includeSubDomains'.",
    ),
    "content-security-policy": (
        Severity.MEDIUM,
        "No Content-Security-Policy. For any HTML surface this removes a key "
        "defense against XSS and data injection.",
        "Define a restrictive Content-Security-Policy header.",
    ),
    "x-content-type-options": (
        Severity.LOW,
        "Missing 'X-Content-Type-Options: nosniff'; browsers may MIME-sniff "
        "responses and execute unexpected content types.",
        "Add 'X-Content-Type-Options: nosniff'.",
    ),
    "x-frame-options": (
        Severity.LOW,
        "No X-Frame-Options (and no CSP frame-ancestors); the response can be "
        "framed, enabling clickjacking.",
        "Add 'X-Frame-Options: DENY' or a CSP 'frame-ancestors' directive.",
    ),
    "referrer-policy": (
        Severity.INFO,
        "No Referrer-Policy set; full URLs may leak to third parties via the "
        "Referer header.",
        "Add 'Referrer-Policy: no-referrer' or 'strict-origin-when-cross-origin'.",
    ),
}


class SecurityHeadersCheck(LiveCheck):
    id = "APSEC-HDR-001"
    name = "Recommended security headers present"
    quick = True

    def run(self, client: httpx.Client, base_url: str) -> Iterable[Finding]:
        resp = client.get(base_url)
        headers = resp.headers  # httpx.Headers is case-insensitive
        has_csp = "content-security-policy" in headers

        for name, (severity, description, remediation) in _EXPECTED.items():
            if name in headers:
                continue
            # X-Frame-Options is satisfied by a CSP frame-ancestors directive.
            if name == "x-frame-options" and has_csp and "frame-ancestors" in headers.get(
                "content-security-policy", ""
            ):
                continue
            yield Finding(
                check_id=self.id,
                title=f"Missing security header: {name}",
                severity=severity,
                location=f"{base_url} (response headers)",
                description=description,
                remediation=remediation,
                references=[_OWASP_MISCONFIG],
            )
