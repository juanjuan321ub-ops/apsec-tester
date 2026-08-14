"""Passive subdomain sources.

Passive = we only query public, third-party OSINT data (Certificate Transparency
logs), never the target itself. This is standard, low-noise bug-bounty recon and
does not touch the customer's infrastructure.
"""

from __future__ import annotations

import httpx

from apsec.core.logger import get_logger

log = get_logger("apsec.recon.sources")


async def crtsh_subdomains(client: httpx.AsyncClient, domain: str) -> set[str]:
    """Query crt.sh Certificate Transparency logs for subdomains of ``domain``."""
    subs: set[str] = set()
    try:
        resp = await client.get(
            "https://crt.sh/", params={"q": f"%.{domain}", "output": "json"}
        )
    except httpx.RequestError as exc:
        log.warning("crt.sh query for %s failed: %s", domain, exc)
        return subs
    if resp.status_code != 200:
        return subs
    try:
        rows = resp.json()
    except ValueError:
        return subs

    for row in rows:
        name = str(row.get("name_value", ""))
        for line in name.splitlines():
            candidate = line.strip().lstrip("*.").lower()
            if candidate.endswith(domain):
                subs.add(candidate)
    log.debug("crt.sh: %d subdomain(s) for %s", len(subs), domain)
    return subs
