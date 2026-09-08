from __future__ import annotations

from typing import Any

import httpx

from purpleloop.control.phase1_tools import PHASE1_TOOLS
from purpleloop.control.tools import ToolRegistry
from purpleloop.fixture.app import FixtureState, create_apps
from purpleloop.runtime.runtime import SafetyRuntime
from purpleloop.schemas.action import ActionRequest, ActionTarget, BudgetRequest, SideEffectClass
from purpleloop.schemas.authorization import AuthorizationManifest


class InProcessFixture:
    def __init__(
        self, customer: str, control: str, *, data_port: int = 18080, control_port: int = 18081
    ) -> None:
        self.state = FixtureState(customer, control)
        apps = create_apps(self.state)
        self.transports = {
            port: httpx.ASGITransport(app=app)
            for port, app in zip((data_port, control_port), apps, strict=True)
        }
        self.closed = False

    async def close(self) -> None:
        self.state.dispose()
        self.closed = True


class FixtureController:
    """Control-plane calls use the same runtime, with a separately scoped credential."""

    def __init__(
        self,
        runtime: SafetyRuntime,
        manifest: AuthorizationManifest,
        run_id: str,
        *,
        tools: ToolRegistry = PHASE1_TOOLS,
        control_asset_id: str = "fixture-control",
        credential_handle: str = "fixture-control",
    ) -> None:
        self.runtime, self.manifest, self.run_id = runtime, manifest, run_id
        self.tools = tools
        self.control_asset_id = control_asset_id
        self.credential_handle = credential_handle
        self.counter = 0
        self.last_evidence_ids: tuple[str, ...] = ()

    async def call(self, operation: str, arguments: dict[str, Any] | None = None) -> dict[str, Any]:
        self.counter += 1
        definition = self.tools.lookup("control", f"fixture.{operation}")
        assets = [a for a in self.manifest.assets if a.asset_id == self.control_asset_id]
        if len(assets) != 1:
            raise ValueError("exact control asset required")
        asset = assets[0]
        action = ActionRequest(
            schema_version="1.1.0",
            action_id=f"control-{self.counter}",
            adapter="control",
            operation=definition.operation,
            method=definition.method,
            target=ActionTarget(
                url=f"{asset.scheme}://{asset.host}:{asset.port}{definition.path_template}",
                tenant_id="harness",
            ),
            side_effect=definition.side_effect,
            credential_handle=self.credential_handle,
            idempotency_key=f"control-{self.counter}",
            arguments=arguments or {},
            budget=BudgetRequest(writes=int(definition.side_effect == SideEffectClass.WRITE)),
        )
        result = await self.runtime.run(
            self.manifest, action, run_id=self.run_id, trace_id=f"control-{self.counter}"
        )
        self.last_evidence_ids = result.event_hashes
        if result.status != "completed" or result.result is None:
            raise RuntimeError(result.reason_code)
        return dict(result.result.data["value"])
