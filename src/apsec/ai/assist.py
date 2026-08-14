"""Deterministic triage: rank findings by exploitability & bounty value."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

# Severity weight (matches Severity ordering).
_SEV_WEIGHT = {"CRITICAL": 100, "HIGH": 70, "MEDIUM": 40, "LOW": 15, "INFO": 2}

# Bounty-value multiplier by finding family. BOLA/SQLi/auth-bypass pay best.
_FAMILY_WEIGHT = {
    "APSEC-BOLA": 1.6,   # object-level auth bypass (OWASP API1) — top payer
    "APSEC-SQLI": 1.6,   # injection — often high/critical bounties
    "APSEC-AUTH-010": 1.5,  # unauthenticated access to protected resource
    "APSEC-BFLA": 1.4,   # function-level auth bypass (API5)
    "APSEC-MASS": 1.3,   # mass assignment (API3)
    "APSEC-XSS": 1.2,    # reflected XSS
    "APSEC-CORS": 1.15,
    "APSEC-CHAOS": 1.05,
    "APSEC-HDR": 0.7,    # header hygiene — usually low/no bounty
    "APSEC-INFO": 0.6,
    "APSEC-TLS": 0.9,
    "APSEC-AUTH-00": 0.95,  # static contract auth checks
    "APSEC-RATE": 0.8,
}


@dataclass
class RankedFinding:
    check_id: str
    title: str
    severity: str
    location: str
    score: float
    rationale: str


def _family_weight(check_id: str) -> float:
    for prefix, weight in _FAMILY_WEIGHT.items():
        if check_id.startswith(prefix):
            return weight
    return 1.0


def prioritize(data: dict[str, Any]) -> list[RankedFinding]:
    """Score and sort findings, highest bounty potential first."""
    ranked: list[RankedFinding] = []
    for f in data.get("findings", []):
        sev = str(f.get("severity", "INFO")).upper()
        base = _SEV_WEIGHT.get(sev, 2)
        weight = _family_weight(str(f.get("check_id", "")))
        score = round(base * weight, 1)
        if weight >= 1.4:
            rationale = "High-value class (auth/injection); confirm and report first."
        elif weight >= 1.1:
            rationale = "Moderate value; worth manual confirmation."
        else:
            rationale = "Hygiene/low-bounty; include as supporting evidence."
        ranked.append(
            RankedFinding(
                check_id=str(f.get("check_id", "")),
                title=str(f.get("title", "")),
                severity=sev,
                location=str(f.get("location", "")),
                score=score,
                rationale=rationale,
            )
        )
    ranked.sort(key=lambda r: r.score, reverse=True)
    return ranked


def narrative(data: dict[str, Any]) -> str:
    """A short plain-language summary suitable for a report intro."""
    ranked = prioritize(data)
    counts = data.get("counts", {})
    total = len(ranked)
    if total == 0:
        return "No findings were produced. The target passed the configured checks."

    top = ranked[0]
    crit = counts.get("CRITICAL", 0)
    high = counts.get("HIGH", 0)
    head = (
        f"Scan of {data.get('target', 'the target')} produced {total} finding(s): "
        f"{crit} critical, {high} high."
    )
    focus = (
        f" The highest-priority issue is {top.check_id} ({top.title}) at {top.location}, "
        f"scored {top.score}. {top.rationale}"
    )
    return head + focus
