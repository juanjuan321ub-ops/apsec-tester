"""Core data types shared by checks, engine and reporters."""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import IntEnum
from typing import Any


class Severity(IntEnum):
    """Ordered severity so results can be sorted/filtered numerically."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return self.name


@dataclass(frozen=True)
class Finding:
    """A single security observation produced by a check."""

    check_id: str          # e.g. "APSEC-AUTH-001"
    title: str             # short human title
    severity: Severity
    location: str          # e.g. "GET /users/{id}" or "global"
    description: str       # what is wrong
    remediation: str       # how to fix it
    references: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.label
        return d


@dataclass
class ScanResult:
    """Aggregated output of a full scan run."""

    target: str
    spec_version: str
    api_title: str
    findings: list[Finding] = field(default_factory=list)
    started_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)

    def sorted_findings(self) -> list[Finding]:
        """Highest severity first, then by check id for stable output."""
        return sorted(
            self.findings, key=lambda f: (-int(f.severity), f.check_id, f.location)
        )

    def counts(self) -> dict[str, int]:
        counts = {s.label: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity.label] += 1
        return counts

    @property
    def highest_severity(self) -> Severity:
        return max((f.severity for f in self.findings), default=Severity.INFO)

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "api_title": self.api_title,
            "spec_version": self.spec_version,
            "started_at": self.started_at,
            "counts": self.counts(),
            "findings": [f.to_dict() for f in self.sorted_findings()],
        }
