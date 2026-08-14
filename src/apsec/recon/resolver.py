"""Async DNS resolution built on the stdlib event loop (no extra dependency)."""

from __future__ import annotations

import asyncio
import socket


async def resolve(host: str) -> list[str]:
    """Resolve ``host`` to a sorted list of unique IP addresses, or [] on failure."""
    loop = asyncio.get_running_loop()
    try:
        infos = await loop.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except OSError:
        return []
    return sorted({info[4][0] for info in infos})
