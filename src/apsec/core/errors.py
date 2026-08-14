"""Typed exception hierarchy.

Keeping domain errors explicit lets the CLI layer translate them into
clean exit codes without leaking stack traces to end users.
"""

from __future__ import annotations


class APSecError(Exception):
    """Base class for all recoverable APSec errors."""


class SpecLoadError(APSecError):
    """Raised when an OpenAPI document cannot be read or parsed."""


class SpecValidationError(APSecError):
    """Raised when a document is readable but is not a valid OpenAPI 3.x spec."""


class ScanError(APSecError):
    """Raised when the scan engine fails in an unrecoverable way."""
