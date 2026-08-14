"""Information-disclosure checks via response banners (OWASP API8)."""

from __future__ import annotations

from collections.abc import Iterable

import httpx

from apsec.scanner.live.checks.base import LiveCheck
from apsec.scanner.models import Finding, Severity

_OWASP = "https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/"
_BANNER_HEADERS = ("server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version")


class InfoDisclosureCheck(LiveCheck):
    id = "APSEC-INFO-001"
    name = "No verbose technology banners"
    quick = True

    def run(self, client: httpx.Client, base_url: str) -> Iterable[Finding]:
        resp = client.get(base_url)
        for name in _BANNER_HEADERS:
            value = resp.headers.get(name)
            # Flag banners that expose a specific product/version (contain a digit).
            if value and any(ch.isdigit() for ch in value):
                yield Finding(
                    check_id=self.id,
                    title=f"Technology banner disclosed via '{name}'",
                    severity=Severity.LOW,
                    location=f"{base_url} ({name}: {value})",
                    description=(
                        f"The response advertises {name}: {value!r}. Exposing exact "
                        "product versions helps attackers match known CVEs."
                    ),
                    remediation=f"Remove or genericize the '{name}' response header.",
                    references=[_OWASP],
                )
