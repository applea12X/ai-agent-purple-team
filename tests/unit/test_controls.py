from __future__ import annotations

import asyncio

import pytest

from purpleloop.control import (
    BudgetError,
    BudgetLedger,
    DefaultDenyPolicy,
    KernelState,
    KernelStopped,
    KillSwitch,
    Redactor,
)
from purpleloop.control.policy import PolicyEffect
from purpleloop.schemas import (
    ActionRequest,
    ActionTarget,
    AuthorizationManifest,
    BudgetLimits,
    BudgetRequest,
)


def test_policy_permits_exact_read(manifest: AuthorizationManifest, action: ActionRequest) -> None:
    decision = DefaultDenyPolicy().evaluate(manifest, action)
    assert decision.effect == PolicyEffect.PERMIT
    assert decision.reason_code == "PERMITTED"


@pytest.mark.parametrize(
    ("change", "reason"),
    [
        ({"operation": "admin.read"}, "OPERATION_NOT_ALLOWED"),
        ({"adapter": "generic_http"}, "ADAPTER_NOT_ALLOWED"),
        (
            {
                "target": ActionTarget(
                    url="http://evil.local:8080/records/record-1",
                    tenant_id="tenant-a",
                    resource_id="record-1",
                )
            },
            "OUT_OF_SCOPE",
        ),
        (
            {
                "target": ActionTarget(
                    url="http://fixture.local:8080/records/record-1",
                    tenant_id="tenant-b",
                    resource_id="record-1",
                )
            },
            "OUT_OF_SCOPE",
        ),
    ],
)
def test_policy_denies_scope_and_capability_mutations(
    manifest: AuthorizationManifest,
    action: ActionRequest,
    change: dict[str, object],
    reason: str,
) -> None:
    decision = DefaultDenyPolicy().evaluate(manifest, action.model_copy(update=change))
    assert decision.effect == PolicyEffect.DENY
    assert decision.reason_code == reason


def test_policy_unavailable_fails_closed(
    manifest: AuthorizationManifest, action: ActionRequest
) -> None:
    decision = DefaultDenyPolicy(available=False).evaluate(manifest, action)
    assert not decision.permitted
    assert decision.reason_code == "POLICY_UNAVAILABLE"


@pytest.mark.asyncio
async def test_budget_reservation_is_atomic() -> None:
    ledger = BudgetLedger(BudgetLimits(requests=1, records=1, concurrency=2, wall_time_seconds=10))
    request = BudgetRequest(requests=1, records=1)
    results = await asyncio.gather(
        ledger.reserve(request),
        ledger.reserve(request),
        return_exceptions=True,
    )
    assert sum(not isinstance(result, Exception) for result in results) == 1
    assert sum(isinstance(result, BudgetError) for result in results) == 1
    assert ledger.used.requests == 1


@pytest.mark.asyncio
async def test_kill_switch_cancels_registered_work() -> None:
    switch = KillSwitch()
    task = await switch.spawn(lambda: asyncio.sleep(30))
    await switch.terminate()
    await asyncio.sleep(0)
    assert task.cancelled()
    assert switch.state == KernelState.TERMINATED
    with pytest.raises(KernelStopped):
        await switch.ensure_running()


def test_redactor_removes_secrets_and_headers() -> None:
    redactor = Redactor(("CANARY-SECRET",))
    value = {
        "message": "leaked CANARY-SECRET",
        "Authorization": "Bearer abc.def",
        "nested": ["Bearer token-value"],
    }
    rendered = str(redactor.redact(value))
    assert "CANARY-SECRET" not in rendered
    assert "abc.def" not in rendered
    assert "token-value" not in rendered
