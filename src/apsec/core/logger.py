"""Central logging setup.

A single `get_logger` factory keeps log configuration in one place. Verbosity
is controlled by the CLI (`-v/--verbose`) rather than scattered globals.
"""

from __future__ import annotations

import logging
import sys

_CONFIGURED = False


def configure(verbose: bool = False) -> None:
    """Configure the root `apsec` logger once. Safe to call repeatedly."""
    global _CONFIGURED
    level = logging.DEBUG if verbose else logging.INFO

    logger = logging.getLogger("apsec")
    logger.setLevel(level)

    if not _CONFIGURED:
        handler = logging.StreamHandler(stream=sys.stderr)
        handler.setFormatter(
            logging.Formatter("%(asctime)s %(levelname)-7s %(name)s: %(message)s")
        )
        logger.addHandler(handler)
        _CONFIGURED = True

    # Keep handler level in sync when verbosity toggles between runs.
    for h in logger.handlers:
        h.setLevel(level)


def get_logger(name: str = "apsec") -> logging.Logger:
    """Return a namespaced child logger, e.g. get_logger('apsec.scanner')."""
    return logging.getLogger(name)
