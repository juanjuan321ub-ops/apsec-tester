"""Registry of live checks."""

from apsec.scanner.live.checks.base import LiveCheck
from apsec.scanner.live.checks.headers import SecurityHeadersCheck
from apsec.scanner.live.checks.cors import CorsCheck
from apsec.scanner.live.checks.ratelimit import RateLimitCheck
from apsec.scanner.live.checks.info import InfoDisclosureCheck

ALL_LIVE_CHECKS: list[type[LiveCheck]] = [
    SecurityHeadersCheck,
    CorsCheck,
    InfoDisclosureCheck,
    RateLimitCheck,
]

__all__ = ["LiveCheck", "ALL_LIVE_CHECKS"]
