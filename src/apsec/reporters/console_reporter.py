"""Human-readable console report using the project ANSI palette."""

from __future__ import annotations

from apsec.core import console as c
from apsec.scanner.models import ScanResult, Severity

# Map severity -> palette color for consistent, colorblind-friendly-ish output.
_SEV_COLOR = {
    Severity.CRITICAL: c.R,
    Severity.HIGH: c.R,
    Severity.MEDIUM: c.Y,
    Severity.LOW: c.C,
    Severity.INFO: c.Gr,
}


def render_console(result: ScanResult) -> None:
    """Print a full scan report to stdout."""
    c.banner("APSec Tester — Scan Report")
    print()
    c.info(f"API:    {result.api_title}")
    c.info(f"Spec:   OpenAPI {result.spec_version}")
    c.info(f"Target: {result.target}")
    print()

    findings = result.sorted_findings()
    if not findings:
        c.ok("No issues found by the static checks. ✨")
        _print_summary(result)
        return

    for f in findings:
        color = _SEV_COLOR.get(f.severity, c.Gr)
        tag = c.paint(f" {f.severity.label:^8} ", color)
        print(f"{tag} {c.paint(f.check_id, c.Gr)}  {f.title}")
        print(f"          {c.paint('at', c.Gr)} {f.location}")
        print(f"          {f.description}")
        print(f"          {c.paint('fix:', c.G)} {f.remediation}")
        for ref in f.references:
            c.dim(f"          ref: {ref}")
        print()

    _print_summary(result)


def _print_summary(result: ScanResult) -> None:
    counts = result.counts()
    parts = []
    for sev in reversed(Severity):  # CRITICAL first
        n = counts[sev.label]
        if n:
            color = _SEV_COLOR.get(sev, c.Gr)
            parts.append(c.paint(f"{n} {sev.label}", color))
    summary = "  ".join(parts) if parts else c.paint("clean", c.G)
    print(c.paint("─" * 60, c.Gr))
    print(f"Summary: {summary}")
