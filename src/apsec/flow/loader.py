"""Load an abuse-case flow from a YAML file."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from apsec.core.errors import SpecLoadError
from apsec.core.logger import get_logger
from apsec.flow.models import Flow, Identity, Step

log = get_logger("apsec.flow.loader")

_VALID_ABUSE = {"bola", "bfla", "unauth", "mass_assignment"}


def _parse_step(raw: dict[str, Any], index: int) -> Step:
    if "id" not in raw:
        raise SpecLoadError(f"flow step #{index} is missing 'id'")
    abuse = [str(a).lower() for a in (raw.get("abuse") or [])]
    unknown = set(abuse) - _VALID_ABUSE
    if unknown:
        raise SpecLoadError(f"step {raw['id']}: unknown abuse case(s): {sorted(unknown)}")
    expect = raw.get("expect") or {}
    return Step(
        id=str(raw["id"]),
        identity=raw.get("identity"),
        method=str(raw.get("method", "GET")).upper(),
        path=str(raw.get("path", "/")),
        json_body=raw.get("json"),
        headers={str(k): str(v) for k, v in (raw.get("headers") or {}).items()},
        capture={str(k): str(v) for k, v in (raw.get("capture") or {}).items()},
        expect_status=expect.get("status"),
        abuse=abuse,
        mass_assign=dict(raw.get("mass_assign") or {}),
    )


def load_flow(path: str | Path) -> Flow:
    """Parse a flow definition (identities + steps) from YAML."""
    p = Path(path)
    try:
        text = p.read_text(encoding="utf-8")
    except OSError as exc:
        raise SpecLoadError(f"Could not read flow file {p}: {exc}") from exc

    try:
        import yaml

        data = yaml.safe_load(text) or {}
    except Exception as exc:  # yaml.YAMLError and friends
        raise SpecLoadError(f"Invalid YAML in flow file {p}: {exc}") from exc

    if not isinstance(data, dict) or "flow" not in data:
        raise SpecLoadError(f"{p}: expected a top-level 'flow' object")

    identities: dict[str, Identity] = {}
    for name, spec in (data.get("identities") or {}).items():
        headers = {str(k): str(v) for k, v in ((spec or {}).get("headers") or {}).items()}
        identities[str(name)] = Identity(name=str(name), headers=headers)

    flow_spec = data["flow"]
    if not isinstance(flow_spec, dict):
        raise SpecLoadError(f"{p}: 'flow' must be a mapping")
    raw_steps = flow_spec.get("steps") or []
    if not raw_steps:
        raise SpecLoadError(f"{p}: flow has no steps")

    steps = [_parse_step(s, i) for i, s in enumerate(raw_steps)]

    # Validate that every referenced identity exists.
    for step in steps:
        if step.identity is not None and step.identity not in identities:
            raise SpecLoadError(f"step {step.id}: unknown identity {step.identity!r}")

    flow = Flow(
        name=str(flow_spec.get("name", "unnamed flow")),
        steps=steps,
        identities=identities,
        base_url=data.get("base_url"),
    )
    log.debug("Loaded flow %r: %d steps, %d identities", flow.name, len(steps), len(identities))
    return flow
