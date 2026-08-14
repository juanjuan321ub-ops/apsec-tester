"""Active injection heuristics: error-based SQLi and reflected XSS.

These operate on parameterized URLs (e.g. discovered by recon or provided by the
user). For each query parameter we send crafted values and look for high-signal
evidence: database error strings (SQLi) or verbatim reflection of a unique
script marker in an HTML response (XSS). Scope-gated and async.

Heuristic by nature: findings are strong leads to confirm manually, which is
exactly how a bounty hunter works.
"""

from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import httpx

from apsec.core.errors import ScanError
from apsec.core.logger import get_logger
from apsec.core.scope import Scope
from apsec.scanner.models import Finding, ScanResult, Severity

log = get_logger("apsec.scanner.injection")

_DEFAULT_UA = "APSec-Tester/0.1 (+https://github.com/your-org/apsec-tester)"
_OWASP_INJECTION = (
    "https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/"
)

# High-signal database error fingerprints (subset of common engines).
_SQL_ERRORS = [
    re.compile(p, re.IGNORECASE)
    for p in (
        r"SQL syntax.*MySQL",
        r"you have an error in your sql syntax",
        r"warning.*mysqli?_",
        r"unclosed quotation mark after the character string",
        r"quoted string not properly terminated",
        r"ORA-\d{5}",
        r"PostgreSQL.*ERROR",
        r"psql:.*ERROR",
        r"SQLite/JDBCDriver",
        r"SQLite3::",
        r"sqlite3.OperationalError",
        r"Microsoft OLE DB Provider for SQL Server",
        r"Npgsql\.",
    )
]
_SQLI_PAYLOADS = ["'", '"', "')", "' OR '1'='1", "'--"]

# Deterministic, unlikely-to-collide XSS marker.
_XSS_MARKER = "apsecX55r3fl"
_XSS_PAYLOAD = f"<script>{_XSS_MARKER}</script>"


def _with_param(url: str, param: str, value: str) -> str:
    parts = urlsplit(url)
    query = parse_qsl(parts.query, keep_blank_values=True)
    new_query = [(k, value if k == param else v) for k, v in query]
    return urlunsplit(parts._replace(query=urlencode(new_query)))


def _params_of(url: str) -> list[str]:
    return [k for k, _ in parse_qsl(urlsplit(url).query, keep_blank_values=True)]


class InjectionEngine:
    """Fuzz query parameters of URLs for SQLi and reflected XSS."""

    def __init__(self, *, scope: Scope | None = None, timeout: float = 10.0) -> None:
        self.scope = scope
        self.timeout = timeout

    async def scan(self, urls: list[str], client: httpx.AsyncClient | None = None) -> ScanResult:
        owns = client is None
        if client is None:
            client = httpx.AsyncClient(
                timeout=self.timeout, follow_redirects=True, trust_env=False,
                headers={"User-Agent": _DEFAULT_UA},
            )
        try:
            return await self._scan(urls, client)
        finally:
            if owns:
                await client.aclose()

    async def _scan(self, urls: list[str], client: httpx.AsyncClient) -> ScanResult:
        result = ScanResult(target=", ".join(urls[:3]) or "(none)", spec_version="", api_title="Injection scan")
        for url in urls:
            if self.scope is not None and not self.scope.is_in_scope(url):
                log.info("Skipping out-of-scope URL: %s", url)
                continue
            params = _params_of(url)
            if not params:
                log.debug("No query params to fuzz on %s", url)
                continue
            for param in params:
                await self._test_sqli(client, result, url, param)
                await self._test_xss(client, result, url, param)
        return result

    async def _test_sqli(self, client, result, url, param) -> None:
        for payload in _SQLI_PAYLOADS:
            target = _with_param(url, param, payload)
            try:
                resp = await client.get(target)
            except httpx.RequestError:
                continue
            if any(rx.search(resp.text) for rx in _SQL_ERRORS):
                result.add(
                    Finding(
                        check_id="APSEC-SQLI-001",
                        title="Possible SQL injection (error-based)",
                        severity=Severity.CRITICAL,
                        location=f"GET {url} [param: {param}]",
                        description=(
                            f"Injecting {payload!r} into parameter {param!r} triggered a database "
                            "error in the response, a strong indicator of SQL injection."
                        ),
                        remediation=(
                            "Use parameterized queries / prepared statements; never build SQL "
                            "from raw input. Confirm and report with the exact request."
                        ),
                        references=[_OWASP_INJECTION],
                    )
                )
                return  # one finding per param is enough

    async def _test_xss(self, client, result, url, param) -> None:
        target = _with_param(url, param, _XSS_PAYLOAD)
        try:
            resp = await client.get(target)
        except httpx.RequestError:
            return
        ctype = resp.headers.get("content-type", "")
        if _XSS_PAYLOAD in resp.text and "html" in ctype.lower():
            result.add(
                Finding(
                    check_id="APSEC-XSS-001",
                    title="Reflected Cross-Site Scripting (XSS)",
                    severity=Severity.HIGH,
                    location=f"GET {url} [param: {param}]",
                    description=(
                        f"The script payload injected into {param!r} was reflected verbatim in an "
                        "HTML response without encoding, indicating reflected XSS."
                    ),
                    remediation=(
                        "Context-aware output encoding for all user input; set a strict CSP."
                    ),
                    references=[_OWASP_INJECTION],
                )
            )
