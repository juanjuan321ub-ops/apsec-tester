"""SSRF attack-surface check.

Maps to OWASP API Security Top 10 (2023):
* API7:2023 Server Side Request Forgery

Flags client-controlled parameters whose name suggests they carry a URL/host the
server might fetch (webhook, callback, url, target…). It does NOT actively test
for SSRF — it surfaces the parameters worth reviewing.
"""

from __future__ import annotations

from collections.abc import Iterable

from apsec.parsers.openapi import OpenAPIDocument
from apsec.scanner.checks._helpers import op_parameters
from apsec.scanner.checks.base import Check
from apsec.scanner.models import Finding, Severity

_REF = (
    "https://owasp.org/API-Security/editions/2023/en/"
    "0xa7-server-side-request-forgery/"
)

# Nombres de parámetro que sugieren una URL/host controlada por el cliente.
SSRF_PARAM_KEYWORDS = (
    "url", "uri", "webhook", "callback", "target", "dest", "destination",
    "redirect", "fetch", "link", "endpoint", "host", "proxy", "image_url",
    "avatar_url", "next",
)


class SsrfProneParameter(Check):
    """Parameters that accept client-controlled URLs."""

    id = "APSEC-SSRF-001"
    name = "SSRF-prone parameter"

    def run(self, doc: OpenAPIDocument) -> Iterable[Finding]:
        for op in doc.operations():
            for p in op_parameters(op):
                pname = str(p.get("name", ""))
                low = pname.lower()
                if any(
                    kw == low or kw in low.split("_") or low.endswith(kw)
                    for kw in SSRF_PARAM_KEYWORDS
                ):
                    yield Finding(
                        check_id=self.id,
                        title="Parameter with SSRF surface",
                        severity=Severity.MEDIUM,
                        location=op.label,
                        description=(
                            f"{op.label} accepts the parameter '{pname}', whose "
                            "name suggests a client-controlled URL/host. If the "
                            "server requests it, this is an SSRF risk "
                            "(OWASP API7:2023)."
                        ),
                        remediation=(
                            "Validate against an allow-list of destinations, "
                            "resolve and check the IP (block internal/metadata "
                            "ranges), and do not follow redirects."
                        ),
                        references=[_REF],
                    )
