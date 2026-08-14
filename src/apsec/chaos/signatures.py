"""Regex fingerprints for verbose errors and internal disclosure under fault."""

from __future__ import annotations

import re

# Stack traces / framework debug pages across common stacks.
STACK_TRACE = [
    re.compile(p, re.IGNORECASE)
    for p in (
        r"traceback \(most recent call last\)",
        r"\bline \d+, in ",                # Python
        r"\bat [\w.$]+\([\w.]+\.java:\d+\)",  # Java
        r"exception in thread",
        r"org\.springframework\.",
        r"werkzeug",                       # Flask debugger
        r"django\.(core|db)",
        r"actioncontroller|activerecord",  # Rails
        r"php (warning|fatal error|parse error)",
        r"system\.(web|data)\.",           # .NET
        r"microsoft \.net framework",
        r"stack trace:",
        r"nodejs.*at .*\(/",               # Node stack frame
    )
]

# Internal filesystem path disclosure.
PATH_DISCLOSURE = [
    re.compile(p)
    for p in (
        r"/home/[\w.-]+/",
        r"/var/www/",
        r"/usr/local/",
        r"/opt/[\w.-]+/",
        r"/app/[\w./-]+\.py",
        r"[A-Z]:\\\\(?:Users|inetpub|xampp)\\\\",
    )
]


def first_match(patterns: list[re.Pattern[str]], text: str) -> str | None:
    for rx in patterns:
        m = rx.search(text)
        if m:
            return m.group(0)[:120]
    return None
