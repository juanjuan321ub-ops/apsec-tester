"""Live scan engine — orchestrates dynamic checks against a running target."""

from __future__ import annotations

import httpx

from apsec.core.errors import ScanError
from apsec.core.logger import get_logger
from apsec.scanner.live.checks import ALL_LIVE_CHECKS
from apsec.scanner.live.checks.base import LiveCheck
from apsec.scanner.live.rules import CustomRule, run_custom_rules
from apsec.scanner.models import ScanResult

log = get_logger("apsec.scanner.live.engine")

_DEFAULT_TIMEOUT = 10.0
_DEFAULT_UA = "APSec-Tester/0.1 (+https://github.com/your-org/apsec-tester)"


class LiveScanEngine:
    """Run dynamic checks with graceful per-check isolation.

    Modes
    -----
    * ``quick`` — only cheap, single-request checks.
    * ``full``  — every check, including the rate-limit burst probe.
    """

    def __init__(
        self,
        checks: list[type[LiveCheck]] | None = None,
        *,
        mode: str = "full",
        custom_rules: list[CustomRule] | None = None,
    ) -> None:
        if mode not in ("quick", "full"):
            raise ScanError(f"Unknown scan mode: {mode!r} (use 'quick' or 'full').")
        self._check_classes = checks if checks is not None else ALL_LIVE_CHECKS
        self._mode = mode
        self._custom_rules = custom_rules or []

    def scan(self, base_url: str, client: httpx.Client | None = None) -> ScanResult:
        owns_client = client is None
        if client is None:
            client = httpx.Client(
                timeout=_DEFAULT_TIMEOUT,
                follow_redirects=True,
                trust_env=False,  # deterministic: ignore ambient *_PROXY env vars
                headers={"User-Agent": _DEFAULT_UA},
            )
        try:
            return self._scan(base_url, client)
        finally:
            if owns_client:
                client.close()

    def _scan(self, base_url: str, client: httpx.Client) -> ScanResult:
        # Connectivity pre-check — fail fast with a clear message.
        try:
            client.get(base_url)
        except httpx.RequestError as exc:
            raise ScanError(f"Target unreachable: {base_url} ({exc})") from exc

        result = ScanResult(target=base_url, spec_version="", api_title=base_url)

        for check_cls in self._check_classes:
            check = check_cls()
            if self._mode == "quick" and not check.quick:
                log.debug("Skipping %s in quick mode", check.id)
                continue
            try:
                produced = 0
                for finding in check.run(client, base_url):
                    result.add(finding)
                    produced += 1
                log.debug("Live check %s produced %d finding(s)", check.id, produced)
            except httpx.RequestError as exc:
                log.warning("Live check %s network error: %s — skipping", check.id, exc)
            except Exception as exc:  # isolate a faulty check
                log.warning(
                    "Live check %s raised %s: %s — skipping",
                    check.id,
                    type(exc).__name__,
                    exc,
                )

        for finding in run_custom_rules(client, base_url, self._custom_rules):
            result.add(finding)

        log.debug("Live scan complete: %d finding(s)", len(result.findings))
        return result
