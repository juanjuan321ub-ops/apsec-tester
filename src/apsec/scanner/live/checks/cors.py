"""CORS misconfiguration check (OWASP API8)."""

from __future__ import annotations

from collections.abc import Iterable

import httpx

from apsec.scanner.live.checks.base import LiveCheck
from apsec.scanner.models import Finding, Severity

# A probe origin the server should never legitimately trust.
_PROBE_ORIGIN = "https://apsec-probe.example.com"
_OWASP = "https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/"


class CorsCheck(LiveCheck):
    id = "APSEC-CORS-001"
    name = "CORS policy is not overly permissive"
    quick = True

    def run(self, client: httpx.Client, base_url: str) -> Iterable[Finding]:
        resp = client.get(base_url, headers={"Origin": _PROBE_ORIGIN})
        acao = resp.headers.get("access-control-allow-origin")
        acac = resp.headers.get("access-control-allow-credentials", "").lower() == "true"

        if acao is None:
            return  # no CORS headers — nothing to flag here

        reflects = acao == _PROBE_ORIGIN
        wildcard = acao == "*"

        if reflects and acac:
            yield Finding(
                check_id=self.id,
                title="CORS reflects arbitrary origin with credentials",
                severity=Severity.CRITICAL,
                location=f"{base_url} (Access-Control-Allow-Origin)",
                description=(
                    f"The server reflected the untrusted origin {_PROBE_ORIGIN!r} "
                    "AND allows credentials. Any malicious site can make "
                    "authenticated cross-origin requests and read the responses."
                ),
                remediation=(
                    "Never reflect arbitrary origins. Allow-list exact trusted "
                    "origins and only set Allow-Credentials for those."
                ),
                references=[_OWASP],
            )
        elif reflects:
            yield Finding(
                check_id=self.id,
                title="CORS reflects arbitrary origin",
                severity=Severity.HIGH,
                location=f"{base_url} (Access-Control-Allow-Origin)",
                description=(
                    f"The server echoed the untrusted origin {_PROBE_ORIGIN!r} in "
                    "Access-Control-Allow-Origin, effectively trusting any site."
                ),
                remediation="Allow-list specific trusted origins instead of reflecting the request origin.",
                references=[_OWASP],
            )
        elif wildcard and acac:
            yield Finding(
                check_id=self.id,
                title="CORS wildcard combined with credentials",
                severity=Severity.HIGH,
                location=f"{base_url} (Access-Control-Allow-Origin)",
                description=(
                    "Access-Control-Allow-Origin '*' together with "
                    "Allow-Credentials is an invalid but dangerous combination "
                    "some stacks still honor."
                ),
                remediation="Do not combine wildcard origin with credentials; allow-list origins.",
                references=[_OWASP],
            )
        elif wildcard:
            yield Finding(
                check_id=self.id,
                title="CORS allows any origin ('*')",
                severity=Severity.LOW,
                location=f"{base_url} (Access-Control-Allow-Origin)",
                description=(
                    "Access-Control-Allow-Origin is '*'. Acceptable for fully "
                    "public data, but risky if any endpoint returns sensitive info."
                ),
                remediation="Restrict origins if any response is non-public.",
                references=[_OWASP],
            )
