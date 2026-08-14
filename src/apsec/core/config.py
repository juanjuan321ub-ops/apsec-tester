"""Static configuration: exit codes and severity gating.

Exit codes are part of the public contract with CI systems, so they live in
one place and are documented in the README.
"""

from __future__ import annotations

from apsec.scanner.models import Severity


class ExitCode:
    """Process exit codes returned by the CLI."""

    OK = 0                 # scan ran, gate passed
    FINDINGS_OVER_GATE = 1 # scan ran, but findings met/exceeded the fail level
    USAGE_ERROR = 2        # bad arguments (Typer/Click default)
    SPEC_ERROR = 3         # spec could not be loaded or validated
    RUNTIME_ERROR = 4      # unexpected internal failure


# User-facing severity names accepted by --fail-on, mapped to the enum.
SEVERITY_BY_NAME = {s.label.lower(): s for s in Severity}


def parse_severity(name: str) -> Severity:
    """Translate a CLI severity name into a Severity, raising KeyError if unknown."""
    return SEVERITY_BY_NAME[name.lower()]
