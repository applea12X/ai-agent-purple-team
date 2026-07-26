from __future__ import annotations

import asyncio

import pytest

from purpleloop.adapters import MockReadAdapter
from purpleloop.schemas import ActionRequest, TargetObservation


async def _authorize(_: TargetObservation) -> None:
    return


@pytest.mark.asyncio
async def test_mock_adapter_is_deterministic(action: ActionRequest) -> None:
    adapter = MockReadAdapter({"record-1": {"id": "record-1", "value": "synthetic"}})
    await adapter.preflight(action)
    first = await adapter.execute(action, credential=None, authorize_target=_authorize)
    second = await adapter.execute(action, credential=None, authorize_target=_authorize)
    assert first.data == second.data
    assert await adapter.postcondition(action, first)


@pytest.mark.asyncio
async def test_mock_adapter_cancellation(action: ActionRequest) -> None:
    adapter = MockReadAdapter(delay_seconds=30)
    task = asyncio.create_task(
        adapter.execute(action, credential=None, authorize_target=_authorize)
    )
    await asyncio.sleep(0)
    await adapter.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
