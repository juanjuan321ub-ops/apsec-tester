"""Tiny, dependency-free ANSI console.

Portability first: we do NOT hard-depend on `rich` for basic output so the
CLI degrades gracefully on minimal terminals and CI. Colors auto-disable when
output is not a TTY or when the NO_COLOR convention is set.

Project palette (kept identical across the toolchain):
    G  green   \x1b[32m
    C  cyan    \x1b[36m
    Y  yellow  \x1b[33m
    R  red     \x1b[31m
    Gr grey    \x1b[90m
    B  bold    \x1b[1m
    Rs reset   \x1b[0m
"""

from __future__ import annotations

import os
import sys

# --- Raw palette -----------------------------------------------------------
G = "\x1b[32m"
C = "\x1b[36m"
Y = "\x1b[33m"
R = "\x1b[31m"
Gr = "\x1b[90m"
B = "\x1b[1m"
Rs = "\x1b[0m"


def _color_enabled() -> bool:
    """Colors on only for real terminals and when the user hasn't opted out."""
    if os.environ.get("NO_COLOR") is not None:
        return False
    if os.environ.get("APSEC_FORCE_COLOR") == "1":
        return True
    return sys.stdout.isatty()


_ENABLED = _color_enabled()


def paint(text: str, color: str) -> str:
    """Wrap ``text`` in ``color`` + reset, or return it plain if colors are off."""
    if not _ENABLED:
        return text
    return f"{color}{text}{Rs}"


def info(msg: str) -> None:
    print(paint("ℹ ", C) + msg)


def ok(msg: str) -> None:
    print(paint("✔ ", G) + msg)


def warn(msg: str) -> None:
    print(paint("▲ ", Y) + msg)


def error(msg: str) -> None:
    print(paint("✖ ", R) + msg, file=sys.stderr)


def dim(msg: str) -> None:
    print(paint(msg, Gr))


def banner(title: str) -> None:
    line = "═" * (len(title) + 2)
    print(paint(f"╔{line}╗", C))
    print(paint(f"║ {B}{title}{Rs}{paint('', C)} ║", C) if _ENABLED else f"║ {title} ║")
    print(paint(f"╚{line}╝", C))
