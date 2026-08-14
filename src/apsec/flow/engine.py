"""Flow engine: run the happy path, then execute inverted abuse cases.

Instead of firing generic payloads, it exercises the application's
*authorization and object-handling logic*:

1. Run the declared flow with the owner identity, capturing resource ids.
2. For each step flagged for abuse, replay the request:
   * ``bola``            as every OTHER identity -> object-level auth bypass (API1)
   * ``bfla``            as every OTHER identity -> function-level auth bypass (API5)
   * ``unauth``          with NO credentials      -> broken authentication (API2)
   * ``mass_assignment`` resend body + forbidden fields -> mass assignment (API3/6)

Everything is async and gated by an optional Scope.
"""

from __future__ import annotations

from typing import Any

import httpx

from apsec.core.errors import ScanError
from apsec.core.logger import get_logger
from apsec.core.scope import Scope
from apsec.flow.extract import substitute
from apsec.flow.models import Flow, Step
from apsec.scanner.models import Finding, ScanResult, Severity

log = get_logger("apsec.flow.engine")

_OWASP = {
    "api1": "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/",
    "api2": "https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/",
    "api3": "https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/",
    "api5": "https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/",
}
_DEFAULT_UA = "APSec-Tester/0.1 (+https://github.com/your-org/apsec-tester)"


def _is_success(status: int) -> bool:
    return 200 <= status < 300


def _reflects(data: Any, key: str, value: Any) -> bool:
    """True if a (key == value) pair appears anywhere in a nested JSON structure."""
    if isinstance(data, dict):
        for k, v in data.items():
            if k == key and v == value:
                return True
            if _reflects(v, key, value):
                return True
    elif isinstance(data, list):
        return any(_reflects(item, key, value) for item in data)
    return False


class FlowEngine:
    """Execute a flow and its derived authorization/property-abuse cases."""

    def __init__(
        self,
        flow: Flow,
        *,
        base_url: str | None = None,
        scope: Scope | None = None,
        timeout: float = 10.0,
    ) -> None:
        self.flow = flow
        self.base_url = (base_url or flow.base_url or "").rstrip("/")
        if not self.base_url:
            raise ScanError("Flow needs a base_url (set it in the file or pass --base-url).")
        self.scope = scope
        self.timeout = timeout

    def _url(self, path: str) -> str:
        return self.base_url + "/" + path.lstrip("/")

    def _identity_headers(self, name: str | None) -> dict[str, str]:
        if name is None:
            return {}
        ident = self.flow.identities.get(name)
        return dict(ident.headers) if ident else {}

    async def run(self, client: httpx.AsyncClient | None = None) -> ScanResult:
        if self.scope is not None:
            self.scope.assert_in_scope(self.base_url)
        owns = client is None
        if client is None:
            client = httpx.AsyncClient(
                timeout=self.timeout,
                follow_redirects=False,
                trust_env=False,
                headers={"User-Agent": _DEFAULT_UA},
            )
        try:
            return await self._run(client)
        finally:
            if owns:
                await client.aclose()

    async def _run(self, client: httpx.AsyncClient) -> ScanResult:
        result = ScanResult(target=self.base_url, spec_version="", api_title=self.flow.name)
        context: dict[str, Any] = {}

        # --- Happy path: execute flow and gather captured values --------
        for step in self.flow.steps:
            headers = {**self._identity_headers(step.identity), **step.headers}
            path = substitute(step.path, context)
            body = substitute(step.json_body, context)
            url = self._url(path)
            try:
                resp = await client.request(step.method, url, json=body, headers=headers)
            except httpx.RequestError as exc:
                log.warning("Step %s could not reach %s: %s", step.id, url, exc)
                continue

            if step.capture:
                try:
                    payload = resp.json()
                except ValueError:
                    payload = {}
                for var, jsonpath in step.capture.items():
                    from apsec.flow.extract import extract

                    value = extract(payload, jsonpath)
                    if value is not None:
                        context[var] = value
                    else:
                        log.warning("Step %s: capture %r found nothing", step.id, jsonpath)

            if step.expect_status is not None and resp.status_code != step.expect_status:
                result.add(
                    Finding(
                        check_id="APSEC-FLOW-000",
                        title="Flow assumption broke",
                        severity=Severity.INFO,
                        location=f"{step.method} {path} as {step.identity}",
                        description=(
                            f"Step {step.id!r} expected status {step.expect_status} but got "
                            f"{resp.status_code}. Later abuse cases may be unreliable."
                        ),
                        remediation="Verify the flow definition and credentials.",
                    )
                )

        # --- Inverted abuse cases (recomputed with the final context) ---
        for step in self.flow.steps:
            if not step.abuse:
                continue
            path = substitute(step.path, context)
            url = self._url(path)
            body = substitute(step.json_body, context)

            if "bola" in step.abuse:
                await self._replay_as_others(
                    client, result, step, url, body, kind="bola"
                )
            if "bfla" in step.abuse:
                await self._replay_as_others(
                    client, result, step, url, body, kind="bfla"
                )
            if "unauth" in step.abuse:
                await self._check_unauth(client, result, step, url)
            if "mass_assignment" in step.abuse:
                await self._check_mass_assignment(client, result, step, url, body)

        log.debug("Flow complete: %d finding(s)", len(result.findings))
        return result

    async def _replay_as_others(
        self,
        client: httpx.AsyncClient,
        result: ScanResult,
        step: Step,
        url: str,
        body: Any,
        *,
        kind: str,
    ) -> None:
        owner = step.identity
        for name, ident in self.flow.identities.items():
            if name == owner:
                continue
            try:
                resp = await client.request(step.method, url, headers=ident.headers, json=body)
            except httpx.RequestError as exc:
                log.warning("%s probe as %s failed: %s", kind, name, exc)
                continue
            if not _is_success(resp.status_code):
                continue
            if kind == "bola":
                result.add(
                    Finding(
                        check_id="APSEC-BOLA-001",
                        title="Broken Object Level Authorization (IDOR)",
                        severity=Severity.CRITICAL,
                        location=f"{step.method} {url} as {name}",
                        description=(
                            f"Identity {name!r} received HTTP {resp.status_code} accessing a "
                            f"resource owned by {owner!r}. The API does not enforce per-object "
                            "ownership — any user can reach another user's data."
                        ),
                        remediation=(
                            "Enforce object-level authorization server-side: verify the "
                            "authenticated principal may access the requested object id."
                        ),
                        references=[_OWASP["api1"]],
                    )
                )
            else:  # bfla
                result.add(
                    Finding(
                        check_id="APSEC-BFLA-001",
                        title="Broken Function Level Authorization",
                        severity=Severity.HIGH,
                        location=f"{step.method} {url} as {name}",
                        description=(
                            f"Identity {name!r} (lower privilege) received HTTP "
                            f"{resp.status_code} calling a privileged function performed by "
                            f"{owner!r}. Function-level authorization is not enforced."
                        ),
                        remediation=(
                            "Check the caller's role/permission for the function on every "
                            "request, not just in the UI."
                        ),
                        references=[_OWASP["api5"]],
                    )
                )

    async def _check_unauth(
        self, client: httpx.AsyncClient, result: ScanResult, step: Step, url: str
    ) -> None:
        try:
            resp = await client.request(step.method, url)
        except httpx.RequestError as exc:
            log.warning("Unauth probe failed: %s", exc)
            return
        if _is_success(resp.status_code):
            result.add(
                Finding(
                    check_id="APSEC-AUTH-010",
                    title="Unauthenticated access to a protected resource",
                    severity=Severity.HIGH,
                    location=f"{step.method} {url} (no credentials)",
                    description=(
                        f"The resource returned HTTP {resp.status_code} with NO credentials, "
                        f"yet it is served to identity {step.identity!r} in the flow. "
                        "Authentication is not enforced on this endpoint."
                    ),
                    remediation="Require and validate authentication before serving this endpoint.",
                    references=[_OWASP["api2"]],
                )
            )

    async def _check_mass_assignment(
        self, client: httpx.AsyncClient, result: ScanResult, step: Step, url: str, body: Any
    ) -> None:
        if not step.mass_assign:
            return
        base = body if isinstance(body, dict) else {}
        injected = {**base, **step.mass_assign}
        headers = {**self._identity_headers(step.identity), **step.headers}
        try:
            resp = await client.request(step.method, url, headers=headers, json=injected)
        except httpx.RequestError as exc:
            log.warning("Mass-assignment probe failed: %s", exc)
            return
        if not _is_success(resp.status_code):
            return
        try:
            data = resp.json()
        except ValueError:
            return
        reflected = [k for k, v in step.mass_assign.items() if _reflects(data, k, v)]
        if reflected:
            result.add(
                Finding(
                    check_id="APSEC-MASS-001",
                    title="Mass assignment of protected properties",
                    severity=Severity.HIGH,
                    location=f"{step.method} {url}",
                    description=(
                        "The API accepted and reflected client-supplied fields that should be "
                        f"server-controlled: {', '.join(reflected)}. An attacker can set "
                        "privileged properties (e.g. role, balance, is_admin)."
                    ),
                    remediation=(
                        "Bind request bodies to an explicit allow-list of writable fields; "
                        "never trust client input for privileged properties."
                    ),
                    references=[_OWASP["api3"]],
                )
            )
