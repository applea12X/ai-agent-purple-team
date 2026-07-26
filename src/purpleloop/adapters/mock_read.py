from __future__ import annotations

import asyncio
import time
from collections.abc import Awaitable, Callable
from ipaddress import IPv4Address
from typing import Any

from purpleloop.adapters.base import AdapterResult
from purpleloop.schemas.action import ActionRequest, TargetObservation


class MockReadAdapter:
    name = "mock_read"

    def __init__(
        self,
        records: dict[str, dict[str, Any]] | None = None,
        *,
        delay_seconds: float = 0.0,
        observations: tuple[TargetObservation, ...] | None = None,
    ) -> None:
        self._records = records or {}
        self._delay_seconds = delay_seconds
        self._observations = observations
        self.invocations = 0
        self.started = asyncio.Event()
        self._active: set[asyncio.Task[object]] = set()

    async def preflight(self, action: ActionRequest) -> None:
        if action.adapter != self.name or action.operation not in {"health.read", "record.read"}:
            raise ValueError("mock adapter does not support this action")

    async def execute(
        self,
        action: ActionRequest,
        *,
        credential: str | None,
        authorize_target: Callable[[TargetObservation], Awaitable[None]],
    ) -> AdapterResult:
        task = asyncio.current_task()
        if task is not None:
            self._active.add(task)
        started = time.perf_counter()
        try:
            observations = self._observations or (
                TargetObservation(
                    url=action.target.url,
                    resolved_addresses=(IPv4Address("127.0.0.1"),),
                    hop_index=0,
                ),
            )
            for observation in observations:
                await authorize_target(observation)
            self.invocations += 1
            self.started.set()
            if self._delay_seconds:
                await asyncio.sleep(self._delay_seconds)
            if action.operation == "health.read":
                data: dict[str, Any] = {"status": "ok"}
            else:
                resource_id = action.target.resource_id or ""
                data = dict(self._records.get(resource_id, {"id": resource_id, "missing": True}))
            if credential is not None:
                data["credential_used"] = True
            return AdapterResult(
                status="success",
                data=data,
                latency_ms=(time.perf_counter() - started) * 1000,
            )
        finally:
            if task is not None:
                self._active.discard(task)

    async def cancel(self) -> None:
        for task in tuple(self._active):
            task.cancel()

    async def postcondition(self, action: ActionRequest, result: AdapterResult) -> bool:
        return result.status == "success"
