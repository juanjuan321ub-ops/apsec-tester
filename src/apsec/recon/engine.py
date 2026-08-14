"""Recon engine: discover -> scope-filter -> resolve -> probe alive/fingerprint.

Everything is async and every network operation is guarded by the Scope. The
engine refuses to run with an empty scope, so it can never fan out onto the
whole internet.
"""

from __future__ import annotations

import asyncio
import re
from collections.abc import Awaitable, Callable, Iterable

import httpx

from apsec.core.errors import ScanError
from apsec.core.logger import get_logger
from apsec.core.scope import Scope
from apsec.recon.models import Asset
from apsec.recon.resolver import resolve as default_resolver
from apsec.recon.sources import crtsh_subdomains

log = get_logger("apsec.recon.engine")

_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
_DEFAULT_UA = "APSec-Tester/0.1 (+https://github.com/your-org/apsec-tester)"

Source = Callable[[httpx.AsyncClient, str], Awaitable[set[str]]]
Resolver = Callable[[str], Awaitable[list[str]]]


class ReconEngine:
    """Scope-gated asset discovery pipeline."""

    def __init__(
        self,
        scope: Scope,
        *,
        sources: Iterable[Source] = (crtsh_subdomains,),
        resolver: Resolver = default_resolver,
        wordlist: list[str] | None = None,
        concurrency: int = 20,
        timeout: float = 10.0,
    ) -> None:
        if not scope.include:
            raise ScanError("Recon requires a non-empty scope 'include' list.")
        self.scope = scope
        self.sources = list(sources)
        self.resolver = resolver
        self.wordlist = wordlist or []
        self.concurrency = max(1, concurrency)
        self.timeout = timeout

    async def run(self, client: httpx.AsyncClient | None = None) -> list[Asset]:
        owns = client is None
        if client is None:
            client = httpx.AsyncClient(
                timeout=self.timeout,
                follow_redirects=True,
                trust_env=False,
                headers={"User-Agent": _DEFAULT_UA},
            )
        try:
            return await self._run(client)
        finally:
            if owns:
                await client.aclose()

    async def _discover(self, client: httpx.AsyncClient) -> set[str]:
        """Collect candidate hostnames from all sources + wordlist + seeds."""
        candidates: set[str] = set(self.scope.concrete_hosts())
        seeds = self.scope.seeds()

        for domain in seeds:
            for source in self.sources:
                try:
                    candidates |= await source(client, domain)
                except Exception as exc:  # isolate a faulty source
                    log.warning("Source %s failed for %s: %s", source.__name__, domain, exc)
            for word in self.wordlist:
                candidates.add(f"{word}.{domain}")
        return candidates

    async def _process(self, client: httpx.AsyncClient, host: str, sem: asyncio.Semaphore) -> Asset | None:
        async with sem:
            addresses = await self.resolver(host)
            if not addresses:
                return None  # unresolved hosts are noise; drop them
            asset = Asset(host=host, addresses=addresses)
            await self._probe(client, asset)
            return asset

    async def _probe(self, client: httpx.AsyncClient, asset: Asset) -> None:
        """Check if the host answers over HTTPS/HTTP and fingerprint it."""
        for scheme in ("https", "http"):
            url = f"{scheme}://{asset.host}"
            if not self.scope.is_in_scope(url):  # defense in depth
                continue
            try:
                resp = await client.get(url)
            except httpx.RequestError:
                continue
            asset.alive = True
            asset.scheme = scheme
            asset.status = resp.status_code
            asset.server = resp.headers.get("server")
            match = _TITLE_RE.search(resp.text)
            if match:
                asset.title = match.group(1).strip()[:120]
            return

    async def _run(self, client: httpx.AsyncClient) -> list[Asset]:
        candidates = await self._discover(client)
        in_scope = sorted(h for h in candidates if self.scope.is_in_scope(h))
        skipped = len(candidates) - len(in_scope)
        if skipped:
            log.info("Scope filter dropped %d out-of-scope candidate(s)", skipped)
        log.info("Resolving/probing %d in-scope host(s)", len(in_scope))

        sem = asyncio.Semaphore(self.concurrency)
        tasks = [self._process(client, host, sem) for host in in_scope]
        results = await asyncio.gather(*tasks)
        assets = [a for a in results if a is not None]
        assets.sort(key=lambda a: (not a.alive, a.host))
        return assets
