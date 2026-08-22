"""Helpers compartidos por los checks estáticos portados desde el diseño previo.

El modelo `Operation` del standalone expone `raw` (el dict de la operación) pero
no atributos derivados como `is_public`, `parameters` o `responses`. Estos
helpers los reconstruyen sin duplicar lógica en cada check.
"""

from __future__ import annotations

from typing import Any

from apsec.parsers.openapi import OpenAPIDocument, Operation


def effective_security(op: Operation, doc: OpenAPIDocument) -> list[dict[str, list[str]]]:
    """Requisito de seguridad efectivo: el de la operación, o el global si hereda."""
    if op.security is not None:
        return op.security
    return doc.global_security


def is_public(op: Operation, doc: OpenAPIDocument) -> bool:
    """True si la operación no exige autenticación efectiva.

    Un requirement vacío (`{}`) dentro de `security` significa auth opcional, que
    a efectos de seguridad se trata como acceso público.
    """
    sec = effective_security(op, doc)
    if not sec:
        return True
    return any(len(requirement) == 0 for requirement in sec)


def op_responses(op: Operation) -> dict[str, Any]:
    return op.raw.get("responses", {}) or {}


def op_parameters(op: Operation) -> list[dict[str, Any]]:
    params = op.raw.get("parameters", []) or []
    return [p for p in params if isinstance(p, dict)]


def is_deprecated(op: Operation) -> bool:
    return bool(op.raw.get("deprecated", False))


def has_path_param(op: Operation) -> bool:
    return "{" in op.path
