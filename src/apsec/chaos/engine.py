"""Chaos engine: send fault-inducing requests, detect information leakage.

Bug-bounty relevance: an app that returns a stack trace, framework debug page or
internal filesystem path when it hits an unexpected input is leaking information
that helps an attacker (and is itself a reportable finding — sometimes the thread
that leads to RCE). We deliberately malform requests and inspect the fallout.
Scope-gated and async; requests are read-only and non-destructive.
"""

from __future__ import annotations

import httpx

from apsec.chaos.signatures import PATH_DISCLOSURE, STACK_TRACE, first_match
from apsec.core.errors import ScanError
from apsec.core.logger import get_logger
from apsec.core.scope import Scope
from apsec.scanner.models import Finding, ScanResult, Severity

log = get_logger("apsec.chaos.engine")

_DEFAULT_UA = "APSec-Tester/0.1 (+https://github.com/your-org/apsec-tester)"
_OWASP = "https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/"


class ChaosEngine:
    """Induce faults on a target and report information disclosure."""

    def __init__(self, *, scope: Scope | None = None, timeout: float = 10.0) -> None:
        self.scope = scope
        self.timeout = timeout

    async def scan(self, url: str, client: httpx.AsyncClient | None = None) -> ScanResult:
        if self.scope is not None:
            self.scope.assert_in_scope(url)
        owns = client is None
        if client is None:
            client = httpx.AsyncClient(
                timeout=self.timeout, follow_redirects=False, trust_env=False,
                headers={"User-Agent": _DEFAULT_UA},
            )
        try:
            return await self._scan(url, client)
        finally:
            if owns:
                await client.aclose()

    def _faults(self, client: httpx.AsyncClient, url: str):
        """Yield (label, awaitable) fault-inducing requests."""
        sep = "&" if "?" in url else "?"
        return [
            ("malformed-json",
             client.post(url, content=b'{"broken": ', headers={"content-type": "application/json"})),
            ("wrong-content-type",
             client.post(url, content=b"not-json-at-all", headers={"content-type": "application/json"})),
            ("oversized-parameter",
             client.get(f"{url}{sep}apsec_fuzz=" + "A" * 8000)),
            ("array-type-confusion",
             client.get(f"{url}{sep}id[]=1&id[]=2")),
            ("unexpected-method",
             client.request("PATCH", url, content=b"{}")),
        ]

    async def _scan(self, url: str, client: httpx.AsyncClient) -> ScanResult:
        result = ScanResult(target=url, spec_version="", api_title="Chaos scan")
        seen: set[str] = set()

        for label, awaitable in self._faults(client, url):
            try:
                resp = await awaitable
            except httpx.RequestError as exc:
                log.warning("Fault %s could not run: %s", label, exc)
                continue

            body = resp.text
            trace = first_match(STACK_TRACE, body)
            if trace and "stack" not in seen:
                seen.add("stack")
                result.add(
                    Finding(
                        check_id="APSEC-CHAOS-001",
                        title="Verbose error / stack trace disclosure under fault",
                        severity=Severity.MEDIUM,
                        location=f"{label} -> {url} (HTTP {resp.status_code})",
                        description=(
                            f"A malformed request ({label}) caused the server to return a stack "
                            f"trace or debug page. Evidence: {trace!r}. This leaks framework, "
                            "versions and internal logic to attackers."
                        ),
                        remediation=(
                            "Disable debug mode in production; return generic error responses and "
                            "log details server-side only."
                        ),
                        references=[_OWASP],
                    )
                )

            path = first_match(PATH_DISCLOSURE, body)
            if path and "path" not in seen:
                seen.add("path")
                result.add(
                    Finding(
                        check_id="APSEC-CHAOS-002",
                        title="Internal path disclosure under fault",
                        severity=Severity.LOW,
                        location=f"{label} -> {url} (HTTP {resp.status_code})",
                        description=(
                            f"An error response exposed an internal filesystem path: {path!r}. "
                            "This reveals server layout useful for further attacks."
                        ),
                        remediation="Strip absolute paths from error output; use generic errors.",
                        references=[_OWASP],
                    )
                )
        return result
