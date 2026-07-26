from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any, Protocol

from purpleloop.schemas.action import ActionRequest, TargetObservation
from purpleloop.schemas.common import StrictModel


class AdapterResult(StrictModel):
    status: str
    data: dict[str, Any]
    latency_ms: float


class Adapter(Protocol):
    name: str

    async def preflight(self, action: ActionRequest) -> None: ...

    async def execute(
        self,
        action: ActionRequest,
        *,
        credential: str | None,
        authorize_target: Callable[[TargetObservation], Awaitable[None]],
    ) -> AdapterResult: ...

    async def cancel(self) -> None: ...

    async def postcondition(self, action: ActionRequest, result: AdapterResult) -> bool: ...
