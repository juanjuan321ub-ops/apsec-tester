"""Rate-limiting heuristic (OWASP API4: Unrestricted Resource Consumption)."""

from __future__ import annotations

from collections.abc import Iterable

import httpx

from apsec.scanner.live.checks.base import LiveCheck
from apsec.scanner.models import Finding, Severity

_OWASP = (
    "https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/"
)
_RATE_HEADERS = (
    "retry-after",
    "ratelimit-limit",
    "ratelimit-remaining",
    "x-ratelimit-limit",
    "x-ratelimit-remaining",
)


class RateLimitCheck(LiveCheck):
    id = "APSEC-RATE-001"
    name = "Rate limiting appears to be enforced"
    quick = False  # sends a small burst — only in Full Scan

    #: number of rapid requests used to probe for throttling.
    burst = 8

    def run(self, client: httpx.Client, base_url: str) -> Iterable[Finding]:
        saw_429 = False
        saw_headers = False

        for _ in range(self.burst):
            resp = client.get(base_url)
            if resp.status_code == 429:
                saw_429 = True
                break
            if any(h in resp.headers for h in _RATE_HEADERS):
                saw_headers = True

        if not saw_429 and not saw_headers:
            yield Finding(
                check_id=self.id,
                title="No rate limiting detected",
                severity=Severity.MEDIUM,
                location=f"{base_url} ({self.burst} rapid requests)",
                description=(
                    f"Sent {self.burst} rapid requests without receiving HTTP 429 "
                    "or any RateLimit/Retry-After headers. The endpoint may be "
                    "open to brute-force, credential stuffing and resource abuse."
                ),
                remediation=(
                    "Enforce per-client rate limiting and advertise it via "
                    "RateLimit-* headers; return 429 when limits are exceeded."
                ),
                references=[_OWASP],
            )
