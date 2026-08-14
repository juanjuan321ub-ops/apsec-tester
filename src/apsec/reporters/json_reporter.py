"""Machine-readable JSON report (for CI pipelines and dashboards)."""

from __future__ import annotations

import json
from pathlib import Path

from apsec.core.errors import APSecError
from apsec.scanner.models import ScanResult


def render_json(result: ScanResult, *, indent: int = 2) -> str:
    """Serialize a scan result to a JSON string."""
    return json.dumps(result.to_dict(), indent=indent, ensure_ascii=False)


def write_json(result: ScanResult, path: str | Path, *, indent: int = 2) -> Path:
    """Write the JSON report to ``path``, returning the resolved Path."""
    out = Path(path)
    try:
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(render_json(result, indent=indent), encoding="utf-8")
    except OSError as exc:
        raise APSecError(f"Could not write report to {out}: {exc}") from exc
    return out
