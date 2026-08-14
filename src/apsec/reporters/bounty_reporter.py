"""Bounty-ready Markdown reports (HackerOne / Bugcrowd submission style).

Turns a scan result into per-finding submissions with the sections triagers
expect: summary, severity, affected asset, steps, impact, remediation, refs.
Operates on the portable dict form so it can also convert a saved JSON report.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from apsec.core.errors import APSecError
from apsec.scanner.models import ScanResult

# Qualitative severity -> rough CVSS 3.1 band (guidance, confirm per program).
_CVSS_BAND = {
    "CRITICAL": "9.0–10.0 (Critical)",
    "HIGH": "7.0–8.9 (High)",
    "MEDIUM": "4.0–6.9 (Medium)",
    "LOW": "0.1–3.9 (Low)",
    "INFO": "0.0 (Informational)",
}


def render_bounty(data: dict[str, Any]) -> str:
    """Render a bounty-style Markdown document from a result dict."""
    lines: list[str] = []
    title = data.get("api_title", "Target")
    lines.append(f"# Security Report — {title}")
    lines.append("")
    lines.append(f"- **Target:** `{data.get('target', 'n/a')}`")
    lines.append(f"- **Generated:** {data.get('started_at', 'n/a')}")
    lines.append(f"- **Tool:** APSec Tester")
    lines.append("")
    lines.append(
        "> Each section below is a self-contained submission. Confirm every finding "
        "manually and attach the exact request/response before submitting — automated "
        "leads still require human validation."
    )
    lines.append("")

    findings = data.get("findings", [])
    if not findings:
        lines.append("_No findings to report._")
        return "\n".join(lines)

    for i, f in enumerate(findings, 1):
        sev = str(f.get("severity", "INFO")).upper()
        lines.append("---")
        lines.append("")
        lines.append(f"## {i}. {f.get('title', 'Finding')} ")
        lines.append("")
        lines.append(f"**ID:** `{f.get('check_id', '')}`  ")
        lines.append(f"**Severity:** {sev} — CVSS {_CVSS_BAND.get(sev, 'n/a')}  ")
        lines.append(f"**Affected asset:** `{f.get('location', 'n/a')}`")
        lines.append("")
        lines.append("### Summary")
        lines.append(f.get("description", ""))
        lines.append("")
        lines.append("### Steps to Reproduce")
        lines.append(f"1. Target the affected asset: `{f.get('location', 'n/a')}`.")
        lines.append("2. Reproduce the condition described in the summary.")
        lines.append("3. Capture the full HTTP request and response as evidence.")
        lines.append("")
        lines.append("### Impact")
        lines.append(f.get("description", ""))
        lines.append("")
        lines.append("### Remediation")
        lines.append(f.get("remediation", ""))
        refs = f.get("references", []) or []
        if refs:
            lines.append("")
            lines.append("### References")
            for r in refs:
                lines.append(f"- {r}")
        lines.append("")
    return "\n".join(lines)


def write_bounty(result: ScanResult | dict[str, Any], path: str | Path) -> Path:
    data = result.to_dict() if isinstance(result, ScanResult) else result
    out = Path(path)
    try:
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(render_bounty(data), encoding="utf-8")
    except OSError as exc:
        raise APSecError(f"Could not write bounty report to {out}: {exc}") from exc
    return out


def load_result_dict(path: str | Path) -> dict[str, Any]:
    """Load a previously saved JSON scan report into a dict."""
    p = Path(path)
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except OSError as exc:
        raise APSecError(f"Could not read report {p}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise APSecError(f"Invalid JSON report {p}: {exc}") from exc
