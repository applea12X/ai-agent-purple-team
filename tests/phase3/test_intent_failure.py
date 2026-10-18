"""A model intent the kernel permits but the target refuses is evidence, not a harness error.

Real models get resource ids wrong: qwen2.5:7b-instruct asked for a ``crm.update`` whose subject
was a *ticket* id. That id is signed, so the kernel permits the action; the fixture answers 403
because a ticket is not a CRM subject. The run has to go on and record the refusal, the way a
compile-time refusal already is. Planned actions, kill-switch stops, and exhausted budgets still
fail the run closed.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from purpleloop.adapters.base import AdapterResult, Authorize
from purpleloop.fixture.supportlab.seed import build
from purpleloop.runtime.demo import ROOT
from purpleloop.runtime.runner import RUN_STOP_REASONS, ActionFailed, PurpleTeamRunner
from purpleloop.runtime.runtime import MAX_FAILURE_DETAIL, RuntimeResult, failure_detail
from purpleloop.runtime.supportlab import InProcessSupportlab
from purpleloop.schemas.action import ActionRequest
from purpleloop.schemas.authorization import AuthorizationManifest
from purpleloop.schemas.phase1 import Phase1Scenario, load_scenario
from purpleloop.schemas.phase3 import ModelPin, ProviderProfile

Make = Callable[..., tuple[PurpleTeamRunner, InProcessSupportlab, Path]]

#: A signed org-a resource that is a ticket, not a user: the kernel permits it, the fixture 403s.
TICKET_ID = build(42).ids["ticket-a1"]


class TicketSubjectModel:
    """Asks for a crm.update on a ticket id every turn, as the real model did."""

    profile: ProviderProfile = "offline"

    def __init__(self) -> None:
        self.calls = 0

    @property
    def endpoint(self) -> str | None:
        return None

    async def complete(
        self, *, pin: ModelPin, system: str, prompt: str, deadline: float
    ) -> tuple[str, int, int]:
        self.calls += 1
        intents = [
            {
                "operation": "crm.update",
                "resource_id": TICKET_ID,
                "arguments": {"field": "tier", "value": "escalated"},
            }
        ]
        text = json.dumps({"message": "Escalated.", "tool_intents": intents}, sort_keys=True)
        return text, 10, 10


class Faulting:
    """Delegates to the real adapter registry, failing the actions ``fails`` selects."""

    def __init__(
        self,
        inner: Any,
        fails: Callable[[ActionRequest], bool],
        before_failing: Callable[[], Any] | None = None,
        message: str = "injected failure",
    ) -> None:
        self.inner = inner
        self.name = str(inner.name)
        self.fails = fails
        self.before_failing = before_failing
        self.message = message

    async def preflight(self, action: ActionRequest) -> None:
        await self.inner.preflight(action)

    async def execute(
        self, action: ActionRequest, *, credential: str | None, authorize_target: Authorize
    ) -> AdapterResult:
        if self.fails(action):
            if self.before_failing is not None:
                await self.before_failing()
            raise ValueError(self.message)
        result: AdapterResult = await self.inner.execute(
            action, credential=credential, authorize_target=authorize_target
        )
        return result

    async def postcondition(self, action: ActionRequest, result: AdapterResult) -> bool:
        return bool(await self.inner.postcondition(action, result))

    async def cancel(self) -> None:
        await self.inner.cancel()


def scenario() -> Phase1Scenario:
    return load_scenario(ROOT / "scenarios" / "agent" / "agent-indirect-ticket.yaml")


def ledger(directory: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in (directory / "evidence.jsonl").read_text().splitlines()]


async def test_a_target_refused_intent_is_recorded_and_the_run_completes(
    make_agent_runner: Make, agent_manifest: AuthorizationManifest
) -> None:
    runner, fixture, directory = make_agent_runner(model_provider=TicketSubjectModel())
    summary = await runner.run(
        scenario(), agent_manifest, run_id="ticket-subject", output_dir=directory
    )
    assert summary.status != "error", summary.reason
    assert summary.reason == "PAIRED_EVALUATION"
    assert summary.teardown_complete and fixture.closed

    events = ledger(directory)
    compiled = [e for e in events if e["reason_code"] == "TOOL_INTENT_COMPILED"]
    failed = [e for e in events if e["reason_code"] == "TOOL_INTENT_FAILED"]
    # Every compiled intent was refused by the target, in every leg, and each refusal is recorded.
    assert compiled and len(failed) == len(compiled)
    for event in failed:
        data = event["data"]
        assert data["operation"] == "crm.update"
        assert data["status"] == "failed"
        assert data["runtime_reason"] == "EXECUTION_FAILED"
        assert data["detail"] == "ValueError: fixture transport status 403"
        assert data["events"]
    # The kernel's own failure record now says why, instead of carrying no detail.
    execution_failed = [e for e in events if e["reason_code"] == "EXECUTION_FAILED"]
    assert len(execution_failed) == len(failed)
    assert {e["data"]["detail"] for e in execution_failed} == {
        "ValueError: fixture transport status 403"
    }

    # The refused write is not counted as executed anywhere.
    completed = sum(1 for e in events if e["kind"] == "result" and e["reason_code"] == "COMPLETED")
    assert summary.executed_actions == completed
    for leg in (summary.baseline, summary.replay):
        assert leg is not None
        assert leg.unauthorized_side_effects == 0
        assert leg.security.verdict == "false"
    for name, snapshot in runner.snapshots.items():
        assert snapshot["state"].get("crm_records", []) == [], name


async def test_a_planned_action_failure_still_fails_the_run_closed(
    make_agent_runner: Make, agent_manifest: AuthorizationManifest
) -> None:
    runner, fixture, directory = make_agent_runner()
    runner.runtime.adapter = Faulting(
        runner.runtime.adapter,
        lambda action: action.operation == "agent.ask" and runner.runtime.stage == "attack",
    )
    summary = await runner.run(scenario(), agent_manifest, run_id="planned", output_dir=directory)
    assert summary.status == "error"
    # The run ends on the planned action, and says why in the kernel's own reason code.
    assert summary.reason == "EXECUTION_FAILED"
    assert summary.teardown_complete and fixture.closed
    events = ledger(directory)
    assert not [e for e in events if e["reason_code"] == "TOOL_INTENT_FAILED"]
    [failure] = [
        e for e in events if e["kind"] == "result" and e["reason_code"] == "EXECUTION_FAILED"
    ]
    assert failure["data"] == {"detail": "ValueError: injected failure"}
    [termination] = [e for e in events if e["kind"] == "termination"]
    assert termination["reason_code"] == "EXECUTION_FAILED"


async def test_a_kill_switch_stop_during_an_intent_still_stops_the_run(
    make_agent_runner: Make, agent_manifest: AuthorizationManifest
) -> None:
    runner, fixture, directory = make_agent_runner(model_provider=TicketSubjectModel())
    runner.runtime.adapter = Faulting(
        runner.runtime.adapter,
        lambda action: action.operation == "crm.update",
        before_failing=runner.runtime.kill_switch.pause,
    )
    summary = await runner.run(scenario(), agent_manifest, run_id="paused", output_dir=directory)
    assert summary.status == "error"
    assert summary.reason.startswith("EXECUTION_FAILED")
    assert not [e for e in ledger(directory) if e["reason_code"] == "TOOL_INTENT_FAILED"]


async def test_failure_detail_is_redacted_and_bounded(
    make_agent_runner: Make, agent_manifest: AuthorizationManifest
) -> None:
    runner, _, directory = make_agent_runner(model_provider=TicketSubjectModel())
    runner.runtime.adapter = Faulting(
        runner.runtime.adapter,
        lambda action: action.operation == "crm.update",
        message="upstream said Authorization: Bearer abc.DEF-123 " + "x" * 500,
    )
    summary = await runner.run(scenario(), agent_manifest, run_id="redact", output_dir=directory)
    assert summary.status != "error", summary.reason
    events = ledger(directory)
    details = [
        e["data"]["detail"]
        for e in events
        if e["reason_code"] in {"EXECUTION_FAILED", "TOOL_INTENT_FAILED"}
    ]
    assert details
    for detail in details:
        assert "abc.DEF-123" not in detail
        assert "[REDACTED]" in detail
        assert len(detail) <= MAX_FAILURE_DETAIL + len("[REDACTED]")
    assert "abc.DEF-123" not in (directory / "evidence.jsonl").read_text()


def test_failure_detail_is_one_bounded_line() -> None:
    detail = failure_detail(ValueError("line one\nline two " + "y" * 1000))
    assert "\n" not in detail
    assert detail.startswith("ValueError: line one line two")
    assert len(detail) == MAX_FAILURE_DETAIL


def test_the_failure_detail_is_outside_the_score_hash() -> None:
    plain = RuntimeResult(status="failed", reason_code="EXECUTION_FAILED")
    detailed = plain.model_copy(update={"detail": "ValueError: fixture transport status 403"})
    assert plain.score_hash == detailed.score_hash


@pytest.mark.parametrize("reason", sorted(RUN_STOP_REASONS))
async def test_run_level_denials_of_an_intent_still_propagate(
    make_agent_runner: Make, agent_manifest: AuthorizationManifest, reason: str
) -> None:
    runner, _, _ = make_agent_runner()
    runner.scenario, runner.manifest, runner.run_id = scenario(), agent_manifest, "stop"

    async def denied(action: ActionRequest) -> RuntimeResult:
        return RuntimeResult(status="denied", reason_code=reason)

    runner.submit = denied  # type: ignore[method-assign]
    action = ActionRequest.model_construct(operation="crm.update", action_id="intent-1")
    with pytest.raises(ActionFailed, match=reason) as raised:
        await runner.intent_action(action)
    assert raised.value.reason_code == reason


async def test_a_cancelled_intent_still_cancels(
    make_agent_runner: Make, agent_manifest: AuthorizationManifest
) -> None:
    runner, _, _ = make_agent_runner()
    runner.scenario, runner.manifest, runner.run_id = scenario(), agent_manifest, "cancel"

    async def cancelled(*args: Any, **kwargs: Any) -> RuntimeResult:
        return RuntimeResult(status="cancelled", reason_code="CANCELLED")

    runner.runtime.run = cancelled  # type: ignore[method-assign]
    action = ActionRequest.model_construct(operation="crm.update", action_id="intent-1")
    with pytest.raises(asyncio.CancelledError):
        await runner.intent_action(action)


async def test_a_kernel_denied_intent_is_evidence(
    make_agent_runner: Make, agent_manifest: AuthorizationManifest
) -> None:
    """A per-action kernel denial at execution time is also what the model attempted."""
    runner, _, _ = make_agent_runner()
    runner.scenario, runner.manifest, runner.run_id = scenario(), agent_manifest, "deny"

    async def denied(action: ActionRequest) -> RuntimeResult:
        return RuntimeResult(status="denied", reason_code="TARGET_OUT_OF_SCOPE")

    runner.submit = denied  # type: ignore[method-assign]
    action = ActionRequest.model_construct(operation="crm.update", action_id="intent-1")
    assert await runner.intent_action(action) is None
    [event] = [e for e in runner.runtime.ledger.verify() if e.reason_code == "TOOL_INTENT_FAILED"]
    assert event.data["runtime_reason"] == "TARGET_OUT_OF_SCOPE"
    assert event.data["status"] == "denied"
    assert event.data["detail"] is None
