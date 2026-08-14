"""Base class every security check inherits from.

A check is a pure function over the parsed document: given an
:class:`OpenAPIDocument`, yield zero or more :class:`Finding` objects. Keeping
checks side-effect free makes them trivial to unit test and safe to run in any
order.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterable

from apsec.parsers.openapi import OpenAPIDocument
from apsec.scanner.models import Finding


class Check(ABC):
    """Abstract security check.

    Subclasses must set ``id``, ``name`` and implement :meth:`run`.
    """

    id: str = "APSEC-000"
    name: str = "unnamed check"

    @abstractmethod
    def run(self, doc: OpenAPIDocument) -> Iterable[Finding]:
        """Yield findings for ``doc``. Must not mutate the document."""
        raise NotImplementedError
