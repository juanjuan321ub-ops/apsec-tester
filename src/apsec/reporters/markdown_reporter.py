"""Markdown report — designed to paste straight into a Jira/GitHub ticket."""

from __future__ import annotations

from pathlib import Path

from apsec.core.errors import APSecError
from apsec.scanner.models import ScanResult, Severity

_SEV_EMOJI = {
    Severity.CRITICAL: "🟥",
    Severity.HIGH: "🟥",
    Severity.MEDIUM: "🟧",
    Severity.LOW: "🟦",
    Severity.INFO: "⬜",
}


def render_markdown(result: ScanResult) -> str:
    """Return the scan result as a Markdown document."""
    lines: list[str] = []
    lines.append(f"# 🛡️ APSec Tester — Report: {result.api_title}")
    lines.append("")
    lines.append(f"- **Target:** `{result.target}`")
    lines.append(f"- **Spec:** OpenAPI {result.spec_version}" if result.spec_version else "- **Spec:** n/a")
    lines.append(f"- **Scanned:** {result.started_at}")
    lines.append("")

    counts = result.counts()
    summary = " · ".join(
        f"{_SEV_EMOJI[s]} {counts[s.label]} {s.label}"
        for s in reversed(Severity)
        if counts[s.label]
    ) or "✅ No findings"
    lines.append(f"**Summary:** {summary}")
    lines.append("")

    findings = result.sorted_findings()
    if not findings:
        lines.append("> No issues found by the configured checks. ✨")
        lines.append("")
        return "\n".join(lines)

    # Overview table
    lines.append("| Severity | ID | Title | Location |")
    lines.append("|----------|----|-------|----------|")
    for f in findings:
        title = f.title.replace("|", "\\|")
        loc = f.location.replace("|", "\\|")
        lines.append(f"| {_SEV_EMOJI[f.severity]} {f.severity.label} | `{f.check_id}` | {title} | `{loc}` |")
    lines.append("")

    # Detail sections
    lines.append("## Details")
    lines.append("")
    for f in findings:
        lines.append(f"### {_SEV_EMOJI[f.severity]} {f.check_id} — {f.title}")
        lines.append("")
        lines.append(f"- **Severity:** {f.severity.label}")
        lines.append(f"- **Location:** `{f.location}`")
        lines.append("")
        lines.append(f"**Description:** {f.description}")
        lines.append("")
        lines.append(f"**Remediation:** {f.remediation}")
        if f.references:
            lines.append("")
            lines.append("**References:**")
            for ref in f.references:
                lines.append(f"- {ref}")
        lines.append("")

    return "\n".join(lines)


def write_markdown(result: ScanResult, path: str | Path) -> Path:
    out = Path(path)
    try:
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(render_markdown(result), encoding="utf-8")
    except OSError as exc:
        raise APSecError(f"Could not write Markdown report to {out}: {exc}") from exc
    return out
