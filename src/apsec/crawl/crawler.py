"""Playwright-based crawler — discovers routes a static parser can't see.

Playwright is an OPTIONAL dependency (heavy: it downloads browsers). The core of
APSec never imports it; only this module does, lazily, so the rest of the tool
works without it. Install with::

    pip install "apsec-tester[browser]"
    playwright install chromium

Everything is scope-gated: the crawler only follows in-scope links.
"""

from __future__ import annotations

from urllib.parse import urljoin, urlsplit

from apsec.core.errors import ScanError
from apsec.core.logger import get_logger
from apsec.core.scope import Scope

log = get_logger("apsec.crawl.crawler")


def ensure_playwright():
    """Return playwright's async API, or raise a helpful ScanError if missing."""
    try:
        from playwright.async_api import async_playwright  # type: ignore
    except ImportError as exc:
        raise ScanError(
            "Playwright is not installed. Enable the optional browser extra:\n"
            '  pip install "apsec-tester[browser]"\n'
            "  playwright install chromium"
        ) from exc
    return async_playwright


def _same_or_in_scope(url: str, scope: Scope | None) -> bool:
    return scope is None or scope.is_in_scope(url)


async def crawl(
    base_url: str,
    *,
    scope: Scope | None = None,
    max_pages: int = 25,
    nav_timeout_ms: int = 15000,
) -> list[str]:
    """Breadth-first crawl from ``base_url``; return sorted in-scope URLs found."""
    if scope is not None:
        scope.assert_in_scope(base_url)

    async_playwright = ensure_playwright()

    discovered: set[str] = set()
    visited: set[str] = set()
    queue: list[str] = [base_url]

    async with async_playwright() as p:  # pragma: no cover - requires browser
        browser = await p.chromium.launch(headless=True)
        try:
            page = await browser.new_page()
            while queue and len(visited) < max_pages:
                url = queue.pop(0)
                if url in visited or not _same_or_in_scope(url, scope):
                    continue
                visited.add(url)
                try:
                    await page.goto(url, timeout=nav_timeout_ms, wait_until="domcontentloaded")
                except Exception as exc:  # noqa: BLE001 - browser errors are varied
                    log.warning("Failed to load %s: %s", url, exc)
                    continue

                hrefs = await page.eval_on_selector_all(
                    "a[href]", "els => els.map(e => e.getAttribute('href'))"
                )
                actions = await page.eval_on_selector_all(
                    "form[action]", "els => els.map(e => e.getAttribute('action'))"
                )
                for raw in [*hrefs, *actions]:
                    if not raw:
                        continue
                    absolute = urljoin(url, raw)
                    if urlsplit(absolute).scheme not in ("http", "https"):
                        continue
                    if _same_or_in_scope(absolute, scope):
                        discovered.add(absolute)
                        if absolute not in visited:
                            queue.append(absolute)
        finally:
            await browser.close()

    return sorted(discovered)
