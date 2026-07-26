from __future__ import annotations

import asyncio
import time
from statistics import quantiles
from typing import Any

import pytest

from purpleloop.adapters import MockReadAdapter
from purpleloop.control import KillSwitch
from purpleloop.schemas import ActionRequest, AuthorizationManifest


@pytest.mark.asyncio
async def test_kill_switch_p99_under_two_seconds(
    manifest: AuthorizationManifest,
    action: ActionRequest,
    runtime_factory: Any,
) -> None:
    latencies: list[float] = []
    for index in range(1000):
        switch = KillSwitch()
        runtime, adapter, _ = runtime_factory(
            manifest=manifest,
            adapter=MockReadAdapter(delay_seconds=30),
            kill_switch=switch,
        )
        task = asyncio.create_task(
            runtime.run(
                manifest,
                action,
                run_id=f"kill-{index}",
                trace_id=f"kill-trace-{index}",
            )
        )
        await adapter.started.wait()
        started = time.perf_counter()
        await switch.terminate()
        result = await asyncio.wait_for(task, timeout=2)
        latencies.append(time.perf_counter() - started)
        assert result.status == "cancelled"
    p99 = quantiles(latencies, n=100, method="inclusive")[98]
    print(f"kill-switch active-adapter p99={p99 * 1000:.3f} ms")
    assert p99 <= 2.0
