"""User-defined custom rules loaded from YAML.

This makes APSec extensible without touching Python: a QA can drop a rules file
describing lightweight request/response assertions. Inspired by Nuclei templates.

Example
-------
```yaml
rules:
  - id: CUSTOM-HEALTH-001
    name: Health endpoint must not leak build info
    severity: medium
    request:
      method: GET
      path: /health
    expect:
      status: 200
      header_absent: [x-build-version]
```
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx

from apsec.core.errors import SpecLoadError
from apsec.core.logger import get_logger
from apsec.scanner.models import Finding, Severity

log = get_logger("apsec.scanner.live.rules")

_SEVERITY_BY_NAME = {s.label.lower(): s for s in Severity}


@dataclass
class CustomRule:
    id: str
    name: str
    severity: Severity
    method: str
    path: str
    expect_status: int | None = None
    header_present: list[str] = field(default_factory=list)
    header_absent: list[str] = field(default_factory=list)


def load_rules(path: str | Path) -> list[CustomRule]:
    """Parse a YAML rules file into CustomRule objects."""
    p = Path(path)
    try:
        text = p.read_text(encoding="utf-8")
    except OSError as exc:
        raise SpecLoadError(f"Could not read rules file {p}: {exc}") from exc

    try:
        import yaml

        data = yaml.safe_load(text)
    except Exception as exc:  # yaml.YAMLError and friends
        raise SpecLoadError(f"Invalid YAML in rules file {p}: {exc}") from exc

    if not isinstance(data, dict) or "rules" not in data:
        raise SpecLoadError(f"{p}: expected a top-level 'rules' list")

    rules: list[CustomRule] = []
    for i, raw in enumerate(data.get("rules") or []):
        if not isinstance(raw, dict):
            raise SpecLoadError(f"{p}: rule #{i} is not a mapping")
        request = raw.get("request", {}) or {}
        expect = raw.get("expect", {}) or {}
        sev_name = str(raw.get("severity", "medium")).lower()
        rules.append(
            CustomRule(
                id=str(raw.get("id", f"CUSTOM-{i:03d}")),
                name=str(raw.get("name", "custom rule")),
                severity=_SEVERITY_BY_NAME.get(sev_name, Severity.MEDIUM),
                method=str(request.get("method", "GET")).upper(),
                path=str(request.get("path", "/")),
                expect_status=expect.get("status"),
                header_present=[h.lower() for h in (expect.get("header_present") or [])],
                header_absent=[h.lower() for h in (expect.get("header_absent") or [])],
            )
        )
    log.debug("Loaded %d custom rule(s) from %s", len(rules), p)
    return rules


def _join(base_url: str, path: str) -> str:
    return base_url.rstrip("/") + "/" + path.lstrip("/")


def run_custom_rules(
    client: httpx.Client, base_url: str, rules: list[CustomRule]
) -> Iterable[Finding]:
    """Evaluate each custom rule, yielding a Finding when an expectation fails."""
    for rule in rules:
        url = _join(base_url, rule.path)
        try:
            resp = client.request(rule.method, url)
        except httpx.RequestError as exc:
            log.warning("Custom rule %s could not reach %s: %s", rule.id, url, exc)
            continue

        problems: list[str] = []
        if rule.expect_status is not None and resp.status_code != rule.expect_status:
            problems.append(
                f"expected status {rule.expect_status}, got {resp.status_code}"
            )
        for h in rule.header_present:
            if h not in resp.headers:
                problems.append(f"expected header '{h}' to be present")
        for h in rule.header_absent:
            if h in resp.headers:
                problems.append(f"header '{h}' should be absent but was present")

        if problems:
            yield Finding(
                check_id=rule.id,
                title=rule.name,
                severity=rule.severity,
                location=f"{rule.method} {url}",
                description="Custom rule failed: " + "; ".join(problems) + ".",
                remediation="Adjust the endpoint to satisfy the custom rule expectations.",
                references=[],
            )
