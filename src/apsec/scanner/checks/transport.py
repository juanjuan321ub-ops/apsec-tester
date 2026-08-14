"""Transport-security checks (TLS / server URLs)."""

from __future__ import annotations

from collections.abc import Iterable

from apsec.parsers.openapi import OpenAPIDocument
from apsec.scanner.checks.base import Check
from apsec.scanner.models import Finding, Severity


class HttpsServerCheck(Check):
    """Ensure declared servers use HTTPS."""

    id = "APSEC-TLS-001"
    name = "Servers use HTTPS"

    def run(self, doc: OpenAPIDocument) -> Iterable[Finding]:
        for url in doc.servers:
            lowered = url.lower()
            # Allow templated and relative URLs; only flag explicit http://.
            if lowered.startswith("http://") and "localhost" not in lowered and "127.0.0.1" not in lowered:
                yield Finding(
                    check_id=self.id,
                    title="Server declared over plaintext HTTP",
                    severity=Severity.HIGH,
                    location=f"servers: {url}",
                    description=(
                        f"The server URL {url!r} uses http://. Traffic — including "
                        "credentials and tokens — travels unencrypted and is open "
                        "to interception and tampering."
                    ),
                    remediation="Serve the API exclusively over https:// and enable HSTS.",
                    references=[
                        "https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/"
                    ],
                )
