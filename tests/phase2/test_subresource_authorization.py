"""Browser subresource origin authorization: charged, recorded, never silently dropped."""

from __future__ import annotations

from typing import Any

from purpleloop.adapters.base import AdapterResult, SubresourceDenied
from purpleloop.schemas.action import TargetObservation
from purpleloop.schemas.event import EventKind


class _SubresourceAdapter:
    name = "browser"

    def __init__(self, urls: list[str]) -> None:
        self.urls = urls
        self.results: list[bool] = []

    async def preflight(self, action: Any) -> None:
        return None

    async def execute(
        self, action: Any, *, credential: str | None, authorize_target: Any
    ) -> AdapterResult:
        from ipaddress import IPv4Address

        for url in self.urls:
            observation = TargetObservation(
                url=url,
                resolved_addresses=(IPv4Address("127.0.0.1"),),
                hop_index=0,
                kind="subresource",
            )
            try:
                await authorize_target(observation)
                self.results.append(True)
            except SubresourceDenied:
                self.results.append(False)
        return AdapterResult(status="ok", data={"outcome": "ok", "value": {}}, latency_ms=0)

    async def postcondition(self, action: Any, result: AdapterResult) -> bool:
        return True

    async def cancel(self) -> None:
        return None


async def test_unsigned_subresource_origin_is_denied_and_charged(
    make_supportlab_runner: Any, supportlab_scenarios: Any, supportlab_signed: Any
) -> None:
    from purpleloop.control.lanes import SUPPORTLAB_LANE
    from purpleloop.control.phase2_tools import DATA_PORT
    from purpleloop.control.plan_compiler import compile_step

    scenario = next(s for s in supportlab_scenarios if s.scenario_id == "bola-ticket-ui")
    action = compile_step(
        scenario.clean_steps[0], scenario, supportlab_signed, lane=SUPPORTLAB_LANE
    )
    runner, fixture, _ = make_supportlab_runner()
    # A subresource inside the signed asset is permitted; one to an unsigned origin is denied.
    adapter = _SubresourceAdapter(
        [f"http://127.0.0.1:{DATA_PORT}/ui/assets/logo.png", "http://evil.invalid:9000/x.js"]
    )
    runner.runtime.adapter = adapter
    budget_before = runner.runtime.budgets.used.requests
    await runner.runtime.run(supportlab_signed, action, run_id="sub", trace_id="sub")
    # A subresource inside the signed asset is permitted; the foreign origin is denied.
    assert adapter.results == [True, False]
    # Both subresource attempts were charged to the run budget, never silently dropped.
    assert runner.runtime.budgets.used.requests >= budget_before + 2
    events = runner.runtime.ledger.verify()
    subresource_events = [e for e in events if e.data.get("kind") == "subresource"]
    assert len(subresource_events) == 2
    permitted, denied = subresource_events
    assert permitted.decision == "permit" and denied.decision == "deny"
    assert denied.kind == EventKind.POLICY
    await fixture.close()
