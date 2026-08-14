"""Base class for live checks.

A live check receives an httpx.Client and the base URL, performs one or more
safe (read-only) requests and yields findings. Checks must never send
destructive requests — probing security posture must not change server state.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterable

import httpx

from apsec.scanner.models import Finding


class LiveCheck(ABC):
    """Abstract dynamic check."""

    id: str = "APSEC-LIVE-000"
    name: str = "unnamed live check"
    #: whether this check runs in Quick Scan mode (cheap, single request).
    quick: bool = True

    @abstractmethod
    def run(self, client: httpx.Client, base_url: str) -> Iterable[Finding]:
        """Yield findings for ``base_url`` using ``client``."""
        raise NotImplementedError
