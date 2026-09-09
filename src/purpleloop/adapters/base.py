from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any, Protocol

from purpleloop.schemas.action import ActionRequest, TargetObservation
from purpleloop.schemas.common import StrictModel

#: The runtime's target guard, injected into every adapter execution. Named once so adapters
#: and their collaborators refer to one type rather than restating the signature.
Authorize = Callable[[TargetObservation], Awaitable[None]]


class AdapterResult(StrictModel):
    status: str
    data: dict[str, Any]
    latency_ms: float


class SubresourceDenied(RuntimeError):
    """Raised by the target guard for a blocked browser subresource.

    The enclosing action continues; the request itself is aborted at the routing layer, the
    denial is recorded as a policy event, and the run budget is charged.
    """

    reason_code = "SUBRESOURCE_DENIED"


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
