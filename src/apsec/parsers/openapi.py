"""OpenAPI 3.x loader and light-weight normalizer.

Design choices
--------------
* We deliberately keep dependencies minimal: JSON via stdlib, YAML via PyYAML
  using ``safe_load`` only (never ``load``) — parsing an untrusted contract must
  never execute arbitrary Python. This is our first line of security defense.
* We do NOT resolve remote ``$ref`` URLs. Fetching arbitrary URLs from a spec is
  an SSRF risk; local structural analysis is enough for the static checks.
* Shallow validation always runs (zero deps). Deep validation via
  openapi-spec-validator is layered on top when the library is available.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from apsec.core.errors import SpecLoadError, SpecValidationError
from apsec.core.logger import get_logger

log = get_logger("apsec.parsers.openapi")

# HTTP methods recognized by the OpenAPI Path Item Object.
HTTP_METHODS = ("get", "put", "post", "delete", "options", "head", "patch", "trace")


@dataclass(frozen=True)
class Operation:
    """A single (method, path) operation extracted from the spec."""

    path: str
    method: str
    operation_id: str | None
    summary: str | None
    security: list[dict[str, list[str]]] | None
    raw: dict[str, Any] = field(default_factory=dict, repr=False)

    @property
    def label(self) -> str:
        return f"{self.method.upper()} {self.path}"


@dataclass
class OpenAPIDocument:
    """Normalized, read-only view over an OpenAPI 3.x document."""

    raw: dict[str, Any]
    source: str

    @property
    def version(self) -> str:
        return str(self.raw.get("openapi", ""))

    @property
    def title(self) -> str:
        return str(self.raw.get("info", {}).get("title", "Untitled API"))

    @property
    def servers(self) -> list[str]:
        servers = self.raw.get("servers", []) or []
        return [str(s.get("url", "")) for s in servers if isinstance(s, dict)]

    @property
    def global_security(self) -> list[dict[str, list[str]]]:
        return self.raw.get("security", []) or []

    @property
    def security_schemes(self) -> dict[str, Any]:
        return self.raw.get("components", {}).get("securitySchemes", {}) or {}

    def operations(self) -> list[Operation]:
        """Flatten paths -> operations for easy iteration by checks."""
        ops: list[Operation] = []
        paths = self.raw.get("paths", {}) or {}
        for path, item in paths.items():
            if not isinstance(item, dict):
                continue
            for method in HTTP_METHODS:
                op = item.get(method)
                if not isinstance(op, dict):
                    continue
                ops.append(
                    Operation(
                        path=path,
                        method=method,
                        operation_id=op.get("operationId"),
                        summary=op.get("summary"),
                        security=op.get("security"),
                        raw=op,
                    )
                )
        return ops


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise SpecLoadError(f"Spec file not found: {path}") from exc
    except OSError as exc:
        raise SpecLoadError(f"Could not read spec file {path}: {exc}") from exc


def _parse(text: str, path: Path) -> dict[str, Any]:
    """Parse JSON or YAML into a dict, choosing by extension then falling back."""
    suffix = path.suffix.lower()
    if suffix == ".json":
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise SpecLoadError(f"Invalid JSON in {path}: {exc}") from exc
    else:
        try:
            import yaml
        except ImportError as exc:  # pragma: no cover - environment guard
            raise SpecLoadError(
                "PyYAML is required to parse YAML specs. Install with "
                "'pip install pyyaml' or use a .json spec."
            ) from exc
        try:
            data = yaml.safe_load(text)
        except yaml.YAMLError as exc:
            raise SpecLoadError(f"Invalid YAML in {path}: {exc}") from exc

    if not isinstance(data, dict):
        raise SpecLoadError(f"Spec root must be a mapping/object, got {type(data).__name__}")
    return data


def _validate_shape(data: dict[str, Any], path: Path) -> None:
    """Shallow OpenAPI 3.x sanity check the static analyzers can rely on."""
    version = str(data.get("openapi", ""))
    if not version.startswith("3."):
        raise SpecValidationError(
            f"{path}: unsupported or missing OpenAPI version "
            f"(found {version!r}, expected 3.x)"
        )
    if "paths" not in data or not isinstance(data["paths"], dict):
        raise SpecValidationError(f"{path}: missing or invalid 'paths' object")


def _validate_deep(data: dict[str, Any], path: Path) -> None:
    """Full OpenAPI 3.x validation via openapi-spec-validator, if installed.

    Optional by design (Portability): the tool degrades to the shallow check when
    the library is absent, but gives rigorous, spec-accurate errors when present.
    """
    try:
        from openapi_spec_validator import validate as _validate  # type: ignore
    except ImportError:
        log.debug("openapi-spec-validator not installed; shallow validation only")
        return

    try:
        _validate(data)
    except Exception as exc:  # library raises assorted errors on malformed input
        raise SpecValidationError(f"{path}: OpenAPI validation failed: {exc}") from exc


def load_openapi(spec_path: str | Path, *, deep: bool = True) -> OpenAPIDocument:
    """Load, parse and validate an OpenAPI 3.x document.

    Parameters
    ----------
    deep:
        When True (default) and openapi-spec-validator is installed, run full
        specification validation in addition to the built-in shallow checks.

    Raises
    ------
    SpecLoadError
        If the file cannot be read or parsed.
    SpecValidationError
        If the parsed document is not a valid OpenAPI 3.x spec.
    """
    path = Path(spec_path)
    log.debug("Loading OpenAPI spec from %s", path)

    text = _read_text(path)
    data = _parse(text, path)
    _validate_shape(data, path)
    if deep:
        _validate_deep(data, path)

    doc = OpenAPIDocument(raw=data, source=str(path))
    log.debug(
        "Loaded %r (OpenAPI %s) with %d operations",
        doc.title,
        doc.version,
        len(doc.operations()),
    )
    return doc
