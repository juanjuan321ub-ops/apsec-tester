"""Tiny JSONPath-lite extraction and {placeholder} substitution.

Deliberately minimal — supports dotted paths with optional list indexes such as
``$.data.items[0].id``. Enough to capture resource identifiers from responses
without pulling in a JSONPath dependency.
"""

from __future__ import annotations

import re
from typing import Any

_TOKEN_RE = re.compile(r"([^.\[\]]+)|\[(\d+)\]")
_VAR_RE = re.compile(r"\{(\w+)\}")


def extract(data: Any, path: str) -> Any:
    """Return the value at ``path`` (e.g. '$.a.b[0]') or None if not found."""
    if not path.startswith("$"):
        return None
    cursor = data
    for name, index in _TOKEN_RE.findall(path[1:]):
        if name:
            if isinstance(cursor, dict):
                cursor = cursor.get(name)
            else:
                return None
        elif index:
            if isinstance(cursor, list) and int(index) < len(cursor):
                cursor = cursor[int(index)]
            else:
                return None
        if cursor is None:
            return None
    return cursor


def substitute(obj: Any, context: dict[str, Any]) -> Any:
    """Recursively replace {var} placeholders in strings using ``context``."""
    if isinstance(obj, str):
        return _VAR_RE.sub(lambda m: str(context.get(m.group(1), m.group(0))), obj)
    if isinstance(obj, dict):
        return {k: substitute(v, context) for k, v in obj.items()}
    if isinstance(obj, list):
        return [substitute(v, context) for v in obj]
    return obj
