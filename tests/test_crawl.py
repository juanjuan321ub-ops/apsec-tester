"""Tests for the crawler's optional-dependency guard.

Playwright is not a core dependency; the crawler must fail with a helpful,
typed error when it is absent (rather than an ImportError traceback).
"""

from __future__ import annotations

import pytest

from apsec.core.errors import ScanError
from apsec.core.scope import Scope
from apsec.crawl import crawl, ensure_playwright


def _playwright_installed() -> bool:
    try:
        import playwright.async_api  # noqa: F401
        return True
    except ImportError:
        return False


@pytest.mark.skipif(_playwright_installed(), reason="Playwright is installed")
def test_ensure_playwright_raises_when_missing():
    with pytest.raises(ScanError) as exc:
        ensure_playwright()
    assert "apsec-tester[browser]" in str(exc.value)


@pytest.mark.skipif(_playwright_installed(), reason="Playwright is installed")
async def test_crawl_raises_when_missing():
    with pytest.raises(ScanError):
        await crawl("https://api.example.com", scope=Scope(include=["*.example.com"]))


def test_crawl_refuses_out_of_scope():
    # Scope check happens before the Playwright import, so this is always testable.
    from apsec.core.scope import OutOfScopeError
    import asyncio
    with pytest.raises(OutOfScopeError):
        asyncio.run(crawl("https://evil.com", scope=Scope(include=["*.example.com"])))
