"""Scope allow-list — the safety core of authorized testing.

This is the single most important module for legal, ethical use. Bug-bounty and
pentest work is only lawful inside an explicitly authorized scope. Every network
operation in APSec must pass through :meth:`Scope.is_in_scope` so the tool
physically cannot touch an asset the user was not invited to test.

Scope is declared in a small YAML file::

    include:
      - "*.example.com"
      - "api.example.org"
    exclude:
      - "blog.example.com"      # explicitly out of bounds
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

from apsec.core.errors import SpecLoadError
from apsec.core.logger import get_logger

log = get_logger("apsec.core.scope")


@dataclass
class Scope:
    """An allow/deny list of hostname patterns.

    Patterns are shell-style globs (``fnmatch``): ``*.example.com`` matches any
    subdomain but NOT the apex ``example.com`` (list the apex explicitly if you
    want it). Matching is case-insensitive. ``exclude`` always wins over
    ``include`` — a denied host is never in scope.
    """

    include: list[str] = field(default_factory=list)
    exclude: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.include = [self._norm(p) for p in self.include]
        self.exclude = [self._norm(p) for p in self.exclude]

    @staticmethod
    def _norm(pattern: str) -> str:
        return pattern.strip().lower().rstrip(".")

    @staticmethod
    def host_of(target: str) -> str:
        """Extract a bare hostname from a URL or host[:port] string."""
        target = target.strip()
        if "://" in target:
            return (urlsplit(target).hostname or "").lower()
        return target.split("/")[0].split(":")[0].lower()

    @staticmethod
    def _matches(host: str, patterns: list[str]) -> bool:
        return any(host == p or fnmatch.fnmatch(host, p) for p in patterns)

    def is_in_scope(self, target: str) -> bool:
        """Return True only if ``target``'s host is included and not excluded."""
        host = self.host_of(target)
        if not host:
            return False
        if self._matches(host, self.exclude):
            return False
        return self._matches(host, self.include)

    def assert_in_scope(self, target: str) -> None:
        """Raise if ``target`` is out of scope. Use before any network op."""
        if not self.is_in_scope(target):
            raise OutOfScopeError(
                f"Refusing to touch out-of-scope target: {target!r}. "
                "Add it to the scope 'include' list only if you are authorized."
            )

    def seeds(self) -> list[str]:
        """Domains to feed passive enumeration (wildcards stripped to a root)."""
        return sorted({p.lstrip("*.") for p in self.include})

    def concrete_hosts(self) -> list[str]:
        """Exact hostnames in the include list (no wildcards)."""
        return sorted({p for p in self.include if "*" not in p})


class OutOfScopeError(SpecLoadError):
    """Raised when an operation would touch a host outside the authorized scope."""


def load_scope(path: str | Path) -> Scope:
    """Load a scope definition from a YAML file."""
    p = Path(path)
    try:
        text = p.read_text(encoding="utf-8")
    except OSError as exc:
        raise SpecLoadError(f"Could not read scope file {p}: {exc}") from exc

    try:
        import yaml

        data = yaml.safe_load(text) or {}
    except Exception as exc:  # yaml.YAMLError and friends
        raise SpecLoadError(f"Invalid YAML in scope file {p}: {exc}") from exc

    if not isinstance(data, dict):
        raise SpecLoadError(f"{p}: scope root must be a mapping with 'include'/'exclude'")

    include = data.get("include") or []
    exclude = data.get("exclude") or []
    if not isinstance(include, list) or not isinstance(exclude, list):
        raise SpecLoadError(f"{p}: 'include' and 'exclude' must be lists")
    if not include:
        raise SpecLoadError(f"{p}: scope 'include' must not be empty")

    scope = Scope(include=[str(x) for x in include], exclude=[str(x) for x in exclude])
    log.debug("Loaded scope: %d include, %d exclude", len(scope.include), len(scope.exclude))
    return scope
