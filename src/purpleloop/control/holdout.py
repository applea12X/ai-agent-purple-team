"""The held-out mutation set: near-miss authorization cases run only in the release lane.

Each case is one exact mutation of a known-permitted action -- an aliased host, a cross-tenant
resource, an unsigned resource, a widened method, a control credential on a data operation --
and the expected result is always a denial. The set exists to catch the failure a tuned system
develops: passing everything it was tuned on. It is therefore digest-pinned before use, held
out of every calibration and tuning path (a test asserts nothing outside this module and its
CLI reads the directory), and exercised only by ``purpleloop holdout-check``.

The executor first proves the *unmutated* base action is permitted. A denied base would make
every mutation vacuously "pass", so the base is a positive control, not an assumption.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Literal

from pydantic import Field

from purpleloop.control.lanes import SUPPORTLAB_LANE
from purpleloop.control.policy import DefaultDenyPolicy
from purpleloop.schemas.action import ActionRequest, ActionTarget, BudgetRequest, SideEffectClass
from purpleloop.schemas.authorization import AuthorizationManifest
from purpleloop.schemas.common import StrictModel, digest_data

#: The only fields a mutation may touch. A closed set: a holdout case is a data record, never
#: an instruction, and the executor applies exactly one named mutation per case.
MutableField = Literal[
    "host",
    "scheme",
    "port",
    "path",
    "query",
    "tenant_id",
    "resource_id",
    "operation",
    "method",
    "side_effect",
    "adapter",
    "credential_handle",
]


class HoldoutCase(StrictModel):
    case_id: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{0,63}$")
    description: str = Field(min_length=1, max_length=300)
    field: MutableField
    value: str | int
    expected: Literal["deny"] = "deny"


class HoldoutSet(StrictModel):
    schema_version: Literal["1.4.0"] = "1.4.0"
    cases: tuple[HoldoutCase, ...] = Field(min_length=1)

    def holdout_digest(self) -> str:
        return digest_data(self.model_dump(mode="json"))


class HoldoutResult(StrictModel):
    case_id: str
    field: str
    permitted: bool
    reason_code: str
    #: A case whose mutation the action model itself refuses is a schema-level denial: the
    #: request cannot even be expressed. Recorded distinctly so the report says which wall held.
    denied_by: Literal["policy", "schema"]


class HoldoutError(ValueError):
    pass


def load_holdout(path: Path) -> HoldoutSet:
    raw = json.loads(path.read_text(encoding="utf-8"))
    return HoldoutSet.model_validate(raw)


def _base_action(manifest: AuthorizationManifest) -> ActionRequest:
    """A permitted ``ticket.read`` derived entirely from the signed manifest."""
    grants = manifest.phase2
    if grants is None:
        raise HoldoutError("the holdout base requires supportlab grants")
    candidates = sorted(
        resource
        for scope in grants.ownership
        if scope.tenant_id == "org-a"
        for resource in scope.resource_ids
        if resource.startswith("ticket-")
    )
    if not candidates:
        raise HoldoutError("no signed org-a ticket to build the base action from")
    resource = candidates[0]
    asset = next(asset for asset in manifest.assets if asset.asset_id == "supportlab-data")
    return ActionRequest(
        schema_version="1.1.0",
        action_id="holdout-base",
        adapter="http",
        operation="ticket.read",
        method="GET",
        target=ActionTarget(
            url=f"http://{asset.host}:{asset.port}/api/tickets/{resource}",
            tenant_id="org-a",
            resource_id=resource,
        ),
        side_effect=SideEffectClass.READ,
        credential_handle="supportlab-customer-a",
        idempotency_key="holdout-base",
        arguments={},
        budget=BudgetRequest(requests=1, records=1),
    )


def _mutate(base: ActionRequest, case: HoldoutCase) -> ActionRequest:
    target = base.target
    url_parts = {
        "scheme": "http",
        "host": target.url.split("://")[1].split(":")[0],
        "port": int(target.url.split(":")[2].split("/")[0]),
        "path": "/" + target.url.split("/", 3)[3],
        "query": "",
    }
    updates: dict[str, object] = {}
    if case.field in url_parts:
        url_parts[case.field] = case.value
        url = f"{url_parts['scheme']}://{url_parts['host']}:{url_parts['port']}{url_parts['path']}"
        if url_parts["query"]:
            url = f"{url}?{url_parts['query']}"
        updates["target"] = target.model_copy(update={"url": url})
    elif case.field in {"tenant_id", "resource_id"}:
        updates["target"] = target.model_copy(update={case.field: case.value})
    elif case.field == "side_effect":
        updates["side_effect"] = SideEffectClass(str(case.value))
    else:
        updates[case.field] = case.value
    return base.model_copy(update=updates)


def run_holdout(
    holdout: HoldoutSet, manifest: AuthorizationManifest
) -> tuple[ActionRequest, tuple[HoldoutResult, ...]]:
    """Evaluate every mutation against the real policy engine; the base must be permitted."""
    policy = DefaultDenyPolicy(SUPPORTLAB_LANE.tools)
    base = _base_action(manifest)
    control = policy.evaluate(manifest, base)
    if not control.permitted:
        raise HoldoutError(
            f"the unmutated base action was denied ({control.reason_code}); "
            "mutations against a denied base prove nothing"
        )
    results: list[HoldoutResult] = []
    for case in holdout.cases:
        try:
            mutated = ActionRequest.model_validate(_mutate(base, case).model_dump())
        except ValueError as exc:
            results.append(
                HoldoutResult(
                    case_id=case.case_id,
                    field=case.field,
                    permitted=False,
                    reason_code=f"SCHEMA_REFUSED: {str(exc)[:120]}",
                    denied_by="schema",
                )
            )
            continue
        decision = policy.evaluate(manifest, mutated)
        results.append(
            HoldoutResult(
                case_id=case.case_id,
                field=case.field,
                permitted=decision.permitted,
                reason_code=decision.reason_code,
                denied_by="policy",
            )
        )
    return base, tuple(results)
