"""Scan engine: run every registered check against a parsed document."""

from __future__ import annotations

from apsec.core.errors import ScanError
from apsec.core.logger import get_logger
from apsec.parsers.openapi import OpenAPIDocument
from apsec.scanner.checks import ALL_CHECKS
from apsec.scanner.checks.base import Check
from apsec.scanner.models import ScanResult

log = get_logger("apsec.scanner.engine")


class ScanEngine:
    """Orchestrates check execution.

    One misbehaving check must never abort the whole scan, so each check runs
    inside its own guard. Failures are surfaced as engine logs, not crashes.
    """

    def __init__(self, checks: list[type[Check]] | None = None) -> None:
        self._check_classes = checks if checks is not None else ALL_CHECKS

    def scan(self, doc: OpenAPIDocument) -> ScanResult:
        result = ScanResult(
            target=doc.source,
            spec_version=doc.version,
            api_title=doc.title,
        )

        if not self._check_classes:
            raise ScanError("No checks registered; nothing to scan.")

        for check_cls in self._check_classes:
            try:
                check = check_cls()
                produced = 0
                for finding in check.run(doc):
                    result.add(finding)
                    produced += 1
                log.debug("Check %s produced %d finding(s)", check.id, produced)
            except Exception as exc:  # defensive: isolate a faulty check
                log.warning(
                    "Check %s raised %s: %s — skipping",
                    getattr(check_cls, "id", check_cls.__name__),
                    type(exc).__name__,
                    exc,
                )

        log.debug("Scan complete: %d total finding(s)", len(result.findings))
        return result
