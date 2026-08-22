"""Security checks registry.

Each check subclasses :class:`~apsec.scanner.checks.base.Check` and is registered
here. The engine iterates this list, so adding a new rule is a one-line change.
"""

from apsec.scanner.checks.base import Check
from apsec.scanner.checks.authentication import (
    GlobalSecurityCheck,
    OperationSecurityCheck,
    WeakSecuritySchemeCheck,
)
from apsec.scanner.checks.transport import HttpsServerCheck
from apsec.scanner.checks.data_exposure import SensitiveDataInResponse
from apsec.scanner.checks.ssrf_surface import SsrfProneParameter
from apsec.scanner.checks.inventory import (
    DeprecatedEndpointExposed,
    MissingApiDescription,
    MixedApiVersions,
)

# Order is cosmetic; findings are sorted by severity in the reporter.
ALL_CHECKS: list[type[Check]] = [
    GlobalSecurityCheck,
    OperationSecurityCheck,
    WeakSecuritySchemeCheck,
    HttpsServerCheck,
    SensitiveDataInResponse,
    SsrfProneParameter,
    DeprecatedEndpointExposed,
    MixedApiVersions,
    MissingApiDescription,
]

__all__ = ["Check", "ALL_CHECKS"]
