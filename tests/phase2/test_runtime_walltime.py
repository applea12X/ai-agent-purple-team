"""A wall-time deadline that surfaces as CancelledError is still classified WALL_TIME_EXCEEDED.

`asyncio.timeout` normally raises TimeoutError, but under scheduling contention the cancellation
it triggers can reach the runtime as CancelledError. The kernel must not misreport a wall-time
timeout as an operator cancellation, and a genuine kill-switch cancellation must stay CANCELLED.
"""

from __future__ import annotations

import asyncio
from typing import Any

from purpleloop.adapters.base import AdapterResult
from purpleloop.schemas.action import ActionRequest, TargetObservation


class _CancellingAdapter:
    name = "mock_read"

    def __init__(self, ledger_started_offset: Any) -> None:
        self._offset = ledger_started_offset

    async def preflight(self, action: ActionRequest) -> None:
        return None

    async def execute(
        self, action: ActionRequest, *, credential: Any, authorize_target: Any
    ) -> AdapterResult:
        from ipaddress import IPv4Address

        await authorize_target(
            TargetObservation(
                url=action.target.url, resolved_addresses=(IPv4Address("127.0.0.1"),), hop_index=0
            )
        )
        # Surface a raw CancelledError the way a contended asyncio.timeout can; the offset callback
        # decides whether the wall-time budget is exhausted at that moment.
        self._offset()
        raise asyncio.CancelledError

    async def postcondition(self, action: ActionRequest, result: AdapterResult) -> bool:
        return True

    async def cancel(self) -> None:
        return None


async def test_walltime_cancellation_reported_as_wall_time_exceeded(
    manifest: Any, action: Any, runtime_factory: Any
) -> None:
    def exhaust() -> None:
        runtime.budgets._started -= 10_000  # deadline is now in the past

    adapter = _CancellingAdapter(exhaust)
    runtime, _, _ = runtime_factory(manifest=manifest, adapter=adapter)
    result = await runtime.run(manifest, action, run_id="wt", trace_id="wt")
    assert result.status == "denied"
    assert result.reason_code == "WALL_TIME_EXCEEDED"


async def test_cancellation_with_budget_remaining_stays_cancelled(
    manifest: Any, action: Any, runtime_factory: Any
) -> None:
    # A CancelledError while the wall-time budget still has room is not a timeout: it stays
    # CANCELLED. The reclassification only fires when the budget is genuinely exhausted.
    adapter = _CancellingAdapter(lambda: None)
    runtime, _, _ = runtime_factory(manifest=manifest, adapter=adapter)
    assert runtime.budgets.remaining_wall_time > 0
    result = await runtime.run(manifest, action, run_id="ks", trace_id="ks")
    assert result.status == "cancelled"
    assert result.reason_code == "CANCELLED"
