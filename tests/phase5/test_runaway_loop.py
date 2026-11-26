"""The kernel's runaway-loop detector (loose end 5.3, PRD §7, ADR 0018).

No test here calls a real model: the looping target model and the looping attacker models are
scripted, and every run is on the in-process supportlab fixture.
"""

from __future__ import annotations

import asyncio
import json
import tempfile
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from hypothesis import given, settings
from hypothesis import strategies as st
from pydantic import ValidationError

from purpleloop.control.attacker import BoundedAttacker, Proposal
from purpleloop.control.capabilities import FIELD_CLASSIFICATION, capability_delta
from purpleloop.control.loop_guard import (
    CONTROL_ADAPTER,
    RUNAWAY_LOOP_DETECTED,
    RUNAWAY_LOOP_WOULD_TRIP,
    WINDOW_ORIGIN,
    LoopGuard,
    action_fingerprint,
    action_state_hash,
    outcome_digest,
    rejected_fingerprint,
    step_fingerprint,
)
from purpleloop.control.manifest import ManifestVerifier
from purpleloop.reporting.audit_export import export_audit
from purpleloop.reporting.bundle import verify_bundle
from purpleloop.runtime.governance import agent_manifest_15, committed_admission
from purpleloop.runtime.pinning import SUPPORTLAB_CONTROL
from purpleloop.runtime.supportlab import (
    KEY_ID,
    InProcessSupportlab,
    actor_credentials,
    build_agent_runner,
)
from purpleloop.schemas.action import ActionRequest, ActionTarget, BudgetRequest, SideEffectClass
from purpleloop.schemas.event import EventKind, EvidenceEvent
from purpleloop.schemas.phase1 import Step, load_scenario
from purpleloop.schemas.phase5 import LoopGuardGrant, Phase5Grants

ROOT = Path(__file__).parents[2]
SCENARIO = ROOT / "scenarios" / "agent" / "agent-tool-misuse.yaml"
GUARD = LoopGuardGrant(repeat_limit=3, no_progress_limit=8)
MAILBOX = {
    "operation": "email.send",
    "arguments": {"destination": "org-mailbox", "subject": "Status", "body": "Same again."},
}


# --- builders ------------------------------------------------------------------------------------


def action(**overrides: Any) -> ActionRequest:
    fields: dict[str, Any] = {
        "schema_version": "1.1.0",
        "action_id": "a-1",
        "adapter": "tool",
        "operation": "email.send",
        "method": "POST",
        "target": ActionTarget(url="http://127.0.0.1:28080/tools/email", tenant_id="org-a"),
        "side_effect": SideEffectClass.WRITE,
        "credential_handle": "supportlab-agent-a",
        "idempotency_key": "k-1",
        "arguments": {"destination": "org-mailbox", "subject": "s", "body": "b"},
        "budget": BudgetRequest(writes=1),
    }
    fields.update(overrides)
    return ActionRequest.model_validate(fields)


def step(**overrides: Any) -> Step:
    fields: dict[str, Any] = {
        "schema_version": "1.3.0",
        "node_id": "n-1",
        "adapter": "tool",
        "operation": "email.send",
        "asset_id": "supportlab-data",
        "target_tenant": "org-a",
        "arguments": {"destination": "attacker-sink", "subject": "s", "body": "b"},
    }
    fields.update(overrides)
    return Step.model_validate(fields)


class LoopingModel:
    """A target model that asks for the same tool calls on every turn, whatever it is shown."""

    profile = "offline"

    def __init__(self, intents: list[dict[str, Any]]) -> None:
        self.intents, self.calls = intents, 0

    @property
    def endpoint(self) -> str | None:
        return None

    async def complete(self, **_: Any) -> tuple[str, int, int]:
        self.calls += 1
        return json.dumps({"message": "Again.", "tool_intents": self.intents}), 50, 20


class Lab(InProcessSupportlab):
    """The in-process fixture with the actor tokens it was seeded with."""

    def __init__(self) -> None:
        self.tokens = actor_credentials()
        super().__init__(self.tokens, SUPPORTLAB_CONTROL)


def agent_run(
    tmp_path: Path,
    *,
    guard: LoopGuardGrant | None = GUARD,
    model: Any = None,
    attacker: Any = None,
    scenario: Any = None,
    manifest: Any = None,
    admission: Any = None,
    key: Ed25519PrivateKey | None = None,
) -> tuple[Any, Any, list[EvidenceEvent], Lab, Path]:
    key = key or Ed25519PrivateKey.generate()
    manifest = manifest or agent_manifest_15(key, loop_guard=guard)
    lab = Lab()
    options: dict[str, Any] = {}
    if model is not None:
        options["model_provider"] = model
    if attacker is not None:
        options["attacker"] = attacker
    bundle = tmp_path / "bundle"
    runner = build_agent_runner(
        bundle,
        manifest,
        ManifestVerifier({KEY_ID: key.public_key()}),
        actor_tokens=lab.tokens,
        control=SUPPORTLAB_CONTROL,
        fixture=lab,
        admission=admission or committed_admission(),
        **options,
    )
    summary = asyncio.run(
        runner.run(scenario or load_scenario(SCENARIO), manifest, run_id="loop", output_dir=bundle)
    )
    return summary, runner, runner.runtime.ledger.verify(), lab, bundle


def detections(events: list[EvidenceEvent]) -> list[EvidenceEvent]:
    return [
        e for e in events if e.reason_code == RUNAWAY_LOOP_DETECTED and e.kind == EventKind.POLICY
    ]


def executed(events: list[EvidenceEvent], operation: str) -> int:
    """Completed executions of ``operation``, counted from the ledger's compiled intents."""
    digests = {
        ActionRequest.model_validate(e.data["action"]).digest()
        for e in events
        if e.reason_code == "TOOL_INTENT_COMPILED" and e.data["action"]["operation"] == operation
    }
    return sum(
        1
        for e in events
        if e.kind == EventKind.RESULT
        and e.reason_code == "COMPLETED"
        and e.action_digest in digests
    )


def assert_stopped_at_detection(events: list[EvidenceEvent]) -> None:
    """Nothing on the target plane executes after the first detection, and the run says why.

    This is the assertion a removed or faked detector fails: a detector that records and does not
    refuse leaves completed target-plane results after its event.
    """
    found = detections(events)
    assert found, "no RUNAWAY_LOOP_DETECTED policy event was recorded"
    first = found[0].sequence
    control = {e.action_digest for e in events if e.trace_id.startswith("control-")}
    after = [
        e
        for e in events
        if e.sequence > first
        and e.kind == EventKind.RESULT
        and e.reason_code == "COMPLETED"
        and e.action_digest not in control
    ]
    assert after == []
    termination = events[-1]
    assert termination.kind == EventKind.TERMINATION
    assert termination.reason_code == RUNAWAY_LOOP_DETECTED
    assert termination.data["teardown_complete"] is True


# --- unit: canonical hashing --------------------------------------------------------------------


def test_the_fingerprint_drops_per_run_identity_and_canonicalizes_arguments() -> None:
    first = action()
    renamed = action(action_id="a-99", idempotency_key="k-99", budget=BudgetRequest(writes=2))
    reordered = action(arguments={"body": "b", "subject": "s", "destination": "org-mailbox"})
    assert action_fingerprint(first) == action_fingerprint(renamed) == action_fingerprint(reordered)


@pytest.mark.parametrize(
    "change",
    [
        {"arguments": {"destination": "org-mailbox", "subject": "s", "body": "c"}},
        {"operation": "export.create"},
        {"target": ActionTarget(url="http://127.0.0.1:28080/tools/email", tenant_id="org-b")},
        {"target": ActionTarget(url="http://127.0.0.1:28080/tools/other", tenant_id="org-a")},
        {"credential_handle": "supportlab-agent-b"},
        {"method": "PUT"},
    ],
)
def test_the_fingerprint_moves_with_anything_the_target_sees(change: dict[str, Any]) -> None:
    assert action_fingerprint(action(**change)) != action_fingerprint(action())


def test_step_fingerprints_drop_the_node_identity_and_differ_from_action_fingerprints() -> None:
    assert step_fingerprint(step()) == step_fingerprint(step(node_id="n-7", depends_on=("x",)))
    assert step_fingerprint(step()) != step_fingerprint(step(target_tenant="org-b"))
    assert step_fingerprint(step()) != action_fingerprint(action())
    assert rejected_fingerprint("refund.create") != rejected_fingerprint("<malformed>")


def test_a_write_outcome_is_bound_to_the_write_and_a_read_outcome_is_not() -> None:
    write_a, write_b = action_fingerprint(action()), action_fingerprint(action(operation="x.y"))
    ack = {"value": {"ok": True}}
    assert outcome_digest(write_a, SideEffectClass.WRITE, "ok", ack) != outcome_digest(
        write_b, SideEffectClass.WRITE, "ok", ack
    )
    assert outcome_digest(write_a, SideEffectClass.READ, "ok", ack) == outcome_digest(
        write_b, SideEffectClass.READ, "ok", ack
    )
    assert outcome_digest(write_a, SideEffectClass.READ, "ok", ack) != outcome_digest(
        write_a, SideEffectClass.READ, "ok", {"value": {"ok": False}}
    )


def test_the_action_state_hash_binds_both_halves() -> None:
    assert action_state_hash("a" * 64, WINDOW_ORIGIN) != action_state_hash("a" * 64, "b" * 64)
    assert action_state_hash("a" * 64, WINDOW_ORIGIN) != action_state_hash("c" * 64, WINDOW_ORIGIN)


# --- unit: thresholds, both sides ----------------------------------------------------------------


@pytest.mark.parametrize("limit", [2, 3, 7])
def test_repetition_trips_exactly_on_the_nth_occurrence(limit: int) -> None:
    guard = LoopGuard(LoopGuardGrant(repeat_limit=limit, no_progress_limit=256))
    for _ in range(limit - 1):
        assert guard.boundary("f" * 64, "attack") is None
        assert guard.observe(None) is None
    trip = guard.boundary("f" * 64, "attack")
    assert trip is not None and trip.check == "repetition"
    assert (trip.observed, trip.limit, trip.state_digest) == (limit, limit, WINDOW_ORIGIN)


@pytest.mark.parametrize("limit", [1, 2, 5])
def test_no_progress_trips_exactly_on_the_kth_unchanged_action(limit: int) -> None:
    guard = LoopGuard(LoopGuardGrant(repeat_limit=64, no_progress_limit=limit))
    for index in range(limit - 1):
        assert guard.boundary(f"{index:064x}", "attack") is None
        assert guard.observe(None) is None
    assert guard.boundary("e" * 64, "attack") is None
    trip = guard.observe(None)
    assert trip is not None and trip.check == "no-progress"
    assert (trip.observed, trip.limit) == (limit, limit)


def test_a_new_outcome_is_progress_and_moves_the_state() -> None:
    guard = LoopGuard(LoopGuardGrant(repeat_limit=2, no_progress_limit=2))
    assert guard.boundary("f" * 64, "attack") is None
    assert guard.observe(None) is None
    # The same action again would be its second occurrence in the same state -- unless the
    # state moved in between, which a new outcome does.
    assert guard.boundary("e" * 64, "attack") is None
    assert guard.observe("1" * 64) is None
    assert guard.boundary("f" * 64, "attack") is None
    assert guard.observe("2" * 64) is None
    # A repeated outcome is not progress.
    assert guard.boundary("d" * 64, "attack") is None
    assert guard.observe("2" * 64) is None
    assert guard.boundary("c" * 64, "attack") is None
    trip = guard.observe("1" * 64)
    assert trip is not None and trip.check == "no-progress"


def test_each_stage_is_its_own_window() -> None:
    guard = LoopGuard(LoopGuardGrant(repeat_limit=2, no_progress_limit=2))
    for stage in ("clean", "attack", "score", "replay_clean", "replay"):
        assert guard.boundary("f" * 64, stage) is None
        assert guard.observe(None) is None
    assert guard.boundary("f" * 64, "replay") is not None


@pytest.mark.parametrize(
    "fields",
    [
        {"repeat_limit": 1, "no_progress_limit": 4},
        {"repeat_limit": 65, "no_progress_limit": 4},
        {"repeat_limit": 3, "no_progress_limit": 0},
        {"repeat_limit": 3, "no_progress_limit": 257},
    ],
)
def test_a_meaningless_limit_cannot_be_signed(fields: dict[str, int]) -> None:
    with pytest.raises(ValidationError):
        LoopGuardGrant.model_validate(fields)


# --- contracts: additive, legacy unchanged -------------------------------------------------------


def test_the_grant_is_additive_and_absent_from_legacy_bytes() -> None:
    from purpleloop.reporting.gates import schema_digests
    from purpleloop.runtime.governance import load_public_key
    from purpleloop.schemas.authorization import AuthorizationManifest

    grants = Phase5Grants.model_validate({"action_classes": ["read"]})
    assert grants.loop_guard is None
    assert b"loop_guard" not in grants.canonical_bytes()
    committed = json.loads((ROOT / "baselines" / "schema-digests.json").read_text())["digests"]
    assert schema_digests() == committed
    # A committed 1.4 manifest still verifies against its committed key, byte for byte.
    nightly = AuthorizationManifest.model_validate_json(
        (ROOT / "scenarios" / "nightly" / "manifest.json").read_text()
    )
    public = load_public_key(ROOT / "scenarios" / "nightly" / "authorization-public.pem")
    ManifestVerifier({nightly.key_id: public}).verify(nightly, now=nightly.valid_from)


def test_a_manifest_before_1_5_cannot_carry_the_grant() -> None:
    from purpleloop.runtime.supportlab import supportlab_agent_manifest
    from purpleloop.schemas.authorization import AuthorizationManifest

    data = supportlab_agent_manifest(Ed25519PrivateKey.generate()).model_dump(mode="python")
    data["phase5"] = {"action_classes": ["read", "write"], "loop_guard": GUARD.model_dump()}
    with pytest.raises(ValidationError):
        AuthorizationManifest.model_validate(data)


def test_the_grant_is_classified_as_a_stop_rule_not_a_capability() -> None:
    assert FIELD_CLASSIFICATION["phase5"]["loop_guard"] == "not-capability"
    key = Ed25519PrivateKey.generate()
    armed, disarmed = agent_manifest_15(key, loop_guard=GUARD), agent_manifest_15(key)
    assert capability_delta(disarmed, armed) == frozenset()
    assert capability_delta(armed, disarmed) == frozenset()


def test_a_disarmed_guard_records_nothing_and_lets_the_loop_run(tmp_path: Path) -> None:
    """Without the signed grant the detector is off: the contrast every armed test relies on."""
    summary, runner, events, _, _ = agent_run(
        tmp_path, guard=None, model=LoopingModel([MAILBOX] * 4)
    )
    assert summary.reason == "PAIRED_EVALUATION"
    assert not any(
        e.reason_code in {RUNAWAY_LOOP_DETECTED, RUNAWAY_LOOP_WOULD_TRIP} for e in events
    )
    # Four copies per turn, every turn of every stage: nothing stopped them.
    turns = sum(e.reason_code == "MODEL_CALLED" for e in events)
    assert turns > 1 and executed(events, "email.send") == 4 * turns
    assert not runner.runtime.loop_guard(runner.manifest).armed


# --- kernel property: one boundary, whatever the source -------------------------------------------


class EchoAdapter:
    """Answers every action with its own arguments: distinct actions, distinct outcomes."""

    name = "echo"

    async def preflight(self, action: ActionRequest) -> None:
        return None

    async def execute(
        self, action: ActionRequest, *, credential: Any, authorize_target: Any
    ) -> Any:
        from purpleloop.adapters.base import AdapterResult

        return AdapterResult(status="ok", data={"echo": action.arguments}, latency_ms=0.0)

    async def cancel(self) -> None:
        return None

    async def postcondition(self, action: ActionRequest, result: Any) -> bool:
        return True


class PermitAll:
    policy_digest = "1" * 64

    def evaluate(self, manifest: Any, action: ActionRequest) -> Any:
        from purpleloop.control.policy import PolicyDecision, PolicyEffect

        return PolicyDecision(PolicyEffect.PERMIT, "PERMITTED", self.policy_digest)


def kernel(directory: Path, grant: LoopGuardGrant) -> tuple[Any, Any]:
    """A real SafetyRuntime over a signed 1.5 manifest, with a permit-all policy and echo target."""
    from purpleloop.control.budgets import BudgetLedger
    from purpleloop.control.credentials import InMemoryCredentialBroker
    from purpleloop.control.kill_switch import KillSwitch
    from purpleloop.control.redaction import Redactor
    from purpleloop.runtime.ledger import EvidenceLedger
    from purpleloop.runtime.runtime import SafetyRuntime
    from purpleloop.schemas.authorization import BudgetLimits

    key = Ed25519PrivateKey.generate()
    manifest = agent_manifest_15(key, loop_guard=grant)
    runtime = SafetyRuntime(
        verifier=ManifestVerifier({KEY_ID: key.public_key()}),
        policy=PermitAll(),
        budgets=BudgetLedger(BudgetLimits(requests=10_000, records=10_000, writes=10_000)),
        kill_switch=KillSwitch(),
        credential_broker=InMemoryCredentialBroker({"supportlab-agent-a": "SYNTHETIC"}),
        redactor=Redactor(()),
        adapter=EchoAdapter(),
        ledger=EvidenceLedger(directory / "evidence.jsonl"),
        admission=committed_admission(),
    )
    runtime.stage = "attack"
    return runtime, manifest


def submit_all(runtime: Any, manifest: Any, values: list[int], *, start: int = 0) -> list[Any]:
    """Submit one action per value (its body), stopping as a runner would once latched."""

    async def go() -> list[Any]:
        results = []
        for index, value in enumerate(values, start=start):
            request = action(
                action_id=f"a-{index}",
                idempotency_key=f"k-{index}",
                arguments={"destination": "org-mailbox", "subject": "s", "body": str(value)},
            )
            results.append(await runtime.run(manifest, request, run_id="p", trace_id=f"t-{index}"))
            if runtime.loop_tripped:
                break
        return results

    return asyncio.run(go())


LIMITS = st.builds(
    LoopGuardGrant,
    repeat_limit=st.integers(min_value=2, max_value=6),
    no_progress_limit=st.integers(min_value=1, max_value=6),
)


@settings(max_examples=25, deadline=None)
@given(grant=LIMITS, values=st.lists(st.integers(0, 10_000), min_size=1, max_size=24, unique=True))
def test_property_a_plan_that_never_repeats_never_trips(
    grant: LoopGuardGrant, values: list[int]
) -> None:
    with tempfile.TemporaryDirectory() as directory:
        runtime, manifest = kernel(Path(directory), grant)
        results = submit_all(runtime, manifest, values)
        assert [r.status for r in results] == ["completed"] * len(values)
        assert not runtime.loop_tripped
        assert not any(e.reason_code == RUNAWAY_LOOP_DETECTED for e in runtime.ledger.verify())


@settings(max_examples=25, deadline=None)
@given(
    grant=LIMITS,
    prefix=st.lists(st.integers(0, 999), max_size=6, unique=True),
    cycle=st.lists(st.integers(1_000, 1_999), min_size=1, max_size=4, unique=True),
)
def test_property_a_plan_that_repeats_a_cycle_always_trips_within_its_bound(
    grant: LoopGuardGrant, prefix: list[int], cycle: list[int]
) -> None:
    """Any cycle of actions repeated with unchanged outcomes is stopped, and stopped in time.

    The first pass of the cycle is new information; every later pass changes nothing, so one of
    the two checks must fire within ``min(repeat_limit, no_progress_limit)`` further passes.
    """
    plan = prefix + cycle * (grant.repeat_limit + 1)
    with tempfile.TemporaryDirectory() as directory:
        runtime, manifest = kernel(Path(directory), grant)
        results = submit_all(runtime, manifest, plan)
        assert runtime.loop_tripped
        bound = len(prefix) + len(cycle) * (1 + min(grant.repeat_limit, grant.no_progress_limit))
        assert len(results) <= bound
        trip = runtime.loop_guard(manifest).tripped
        assert trip is not None and trip.observed == trip.limit
        # After the latch the kernel refuses on its own: the runner's check is not what stops it.
        later = submit_all(runtime, manifest, [5_000], start=len(plan))
        assert (later[0].status, later[0].reason_code) == ("denied", RUNAWAY_LOOP_DETECTED)


def test_the_control_plane_is_exempt_and_still_runs_after_a_trip(tmp_path: Path) -> None:
    runtime, manifest = kernel(tmp_path, LoopGuardGrant(repeat_limit=2, no_progress_limit=1))
    submit_all(runtime, manifest, [1, 1])
    assert runtime.loop_tripped
    control = action(adapter=CONTROL_ADAPTER, operation="fixture.teardown", arguments={})
    for index in range(3):
        result = asyncio.run(
            runtime.run(
                manifest,
                control.model_copy(update={"action_id": f"c-{index}"}),
                run_id="p",
                trace_id="c",
            )
        )
        assert result.status == "completed"


# --- integration: the agent lane, every action source --------------------------------------------


def test_a_looping_model_is_stopped_before_the_nth_identical_tool_call(tmp_path: Path) -> None:
    summary, _, events, lab, bundle = agent_run(tmp_path, model=LoopingModel([MAILBOX] * 4))
    assert (summary.status, summary.reason) == ("error", RUNAWAY_LOOP_DETECTED)
    found = detections(events)
    assert len(found) == 1 and found[0].data["check"] == "repetition"
    assert found[0].data["observed"] == GUARD.repeat_limit
    # The first copy is new information and moves the state; copies 2 .. N+1 share one
    # action-state hash, and the N-th occurrence of it (copy N+1) is refused before dispatch.
    assert executed(events, "email.send") == GUARD.repeat_limit
    assert_stopped_at_detection(events)
    assert summary.teardown_complete and lab.closed
    verify_bundle(bundle, allow_partial=True)


def test_a_model_looping_on_a_refused_tool_call_is_stopped(tmp_path: Path) -> None:
    refused = {
        "operation": "crm.update",
        "resource_id": "admin-b",
        "arguments": {"field": "role", "value": "admin"},
    }
    summary, _, events, lab, _ = agent_run(tmp_path, model=LoopingModel([refused] * 4))
    assert summary.reason == RUNAWAY_LOOP_DETECTED
    found = detections(events)
    assert found[0].data["refused"] == "RESOURCE_NOT_SIGNED"
    assert sum(e.reason_code == "TOOL_INTENT_REFUSED" for e in events) == GUARD.repeat_limit
    assert_stopped_at_detection(events)
    assert lab.closed


def test_a_model_looping_on_a_rejected_intent_is_stopped(tmp_path: Path) -> None:
    rejected = {"operation": "refund.create", "arguments": {"amount": "not-a-number"}}
    summary, _, events, _, _ = agent_run(tmp_path, model=LoopingModel([rejected] * 4))
    assert summary.reason == RUNAWAY_LOOP_DETECTED
    assert sum(e.reason_code == "TOOL_INTENT_REJECTED" for e in events) == GUARD.repeat_limit
    assert_stopped_at_detection(events)


def test_a_plan_that_repeats_a_step_is_stopped(tmp_path: Path) -> None:
    scenario = load_scenario(SCENARIO)
    ask = scenario.attack_steps[0]
    repeated = tuple(ask.model_copy(update={"node_id": f"attack-ask-{i}"}) for i in range(4))
    scenario = scenario.model_copy(update={"attack_steps": repeated})
    # A model that never asks for a tool, so only the plan itself repeats.
    summary, _, events, lab, _ = agent_run(
        tmp_path,
        model=LoopingModel([]),
        scenario=scenario,
        guard=LoopGuardGrant(repeat_limit=2, no_progress_limit=8),
    )
    assert summary.reason == RUNAWAY_LOOP_DETECTED
    assert detections(events)[0].stage == "attack"
    assert_stopped_at_detection(events)
    assert lab.closed


class RepeatingAttacker(BoundedAttacker):
    """A bounded attacker whose search yields the same typed proposal again and again."""

    def proposals(self) -> tuple[Proposal, ...]:
        return tuple(
            Proposal(
                index=index,
                depth=1,
                operation="crm.update",
                target_tenant="org-a",
                resource_id="admin-a",
                arguments={"field": "note", "value": "same"},
                rationale="repeat",
            )
            for index in range(6)
        )


def roomy(scenario: Any) -> Any:
    budget = scenario.attack_budget.model_copy(
        update={"requests": 500, "records": 500, "writes": 500}
    )
    return scenario.model_copy(update={"attack_budget": budget})


def test_a_repeating_bounded_attacker_is_stopped(tmp_path: Path) -> None:
    attacker = RepeatingAttacker(
        max_proposals=8,
        max_depth=3,
        operations=["crm.update"],
        own_tenant="org-a",
        resource_id="admin-a",
    )
    summary, _, events, lab, bundle = agent_run(
        tmp_path, attacker=attacker, scenario=roomy(load_scenario(SCENARIO))
    )
    assert summary.reason == RUNAWAY_LOOP_DETECTED
    assert detections(events)[0].stage == "detect"
    assert_stopped_at_detection(events)
    assert lab.closed
    verify_bundle(bundle, allow_partial=True)


class FixedAttackerModel:
    """An attacker model that answers every round with the same proposals."""

    profile = "offline"

    def __init__(self, copies: int) -> None:
        proposal = {
            "operation": "crm.update",
            "target_tenant": "org-a",
            "arguments": {"field": "note", "value": "same"},
        }
        self.text = json.dumps({"proposals": [proposal] * copies})
        self.calls = 0

    @property
    def endpoint(self) -> str | None:
        return None

    async def complete(self, **_: Any) -> Any:
        self.calls += 1
        return self.text, 10, 10


def model_driven(model: Any) -> Any:
    from purpleloop.control.attacker import ModelDrivenAttacker
    from purpleloop.runtime.governance import ATTACKER_PIN

    return ModelDrivenAttacker(
        model,
        ATTACKER_PIN,
        objective="repeat",
        max_proposals=8,
        max_depth=3,
        operations=["crm.update"],
        own_tenant="org-a",
        resource_id="admin-a",
    )


def shadow_events(directory: Path, scenario_id: str) -> list[dict[str, Any]]:
    lines = (directory / scenario_id / "evidence.jsonl").read_text().splitlines()
    return [json.loads(line) for line in lines]


def test_shadow_reports_a_would_be_loop_and_stops_nothing(governance: Any, tmp_path: Path) -> None:
    from purpleloop.runtime.shadow import verify_shadow_bundle

    requested = governance.manifest(proposal_source="model-driven", loop_guard=GUARD)
    scenario = roomy(load_scenario(SCENARIO))
    out = tmp_path / "shadow"
    report, _, _ = governance.shadow(
        requested, out, scenarios=[scenario], attacker=lambda: model_driven(FixedAttackerModel(4))
    )
    assert report.would_be_loops is not None and report.would_be_loops >= 1
    assert report.adapter_calls == 0
    events = shadow_events(out, scenario.scenario_id)
    flagged = [e for e in events if e.get("reason_code") == RUNAWAY_LOOP_WOULD_TRIP]
    assert len(flagged) == report.would_be_loops
    assert all(e["decision"] == "would-deny" and e["schema_version"] == "1.2.0" for e in flagged)
    assert not any(e.get("reason_code") == RUNAWAY_LOOP_DETECTED for e in events)
    # The walk went on past the would-be loop: later proposals were still decided.
    first = min(e["sequence"] for e in flagged)
    assert any(e["kind"] == "shadow-suppressed" and e["sequence"] > first for e in events)
    assert verify_shadow_bundle(out).would_be_loops == report.would_be_loops


def test_the_shadow_loop_count_cannot_be_edited(governance: Any, tmp_path: Path) -> None:
    """The count is recomputed from the ledger, so a faked or deleted count fails verification."""
    from purpleloop.reporting.bundle import inventory
    from purpleloop.runtime.shadow import (
        SHADOW_REPORT_FILE,
        ShadowBundleError,
        verify_shadow_bundle,
    )

    requested = governance.manifest(proposal_source="model-driven", loop_guard=GUARD)
    out = tmp_path / "shadow"
    report, _, _ = governance.shadow(
        requested,
        out,
        scenarios=[roomy(load_scenario(SCENARIO))],
        attacker=lambda: model_driven(FixedAttackerModel(4)),
    )
    stored = json.loads((out / SHADOW_REPORT_FILE).read_text())
    for forged in ((report.would_be_loops or 0) + 5, None):
        if forged is None:
            stored.pop("would_be_loops")
        else:
            stored["would_be_loops"] = forged
        (out / SHADOW_REPORT_FILE).write_text(json.dumps(stored))
        inventory(out, complete=True)
        with pytest.raises(ShadowBundleError, match="disagrees"):
            verify_shadow_bundle(out)


def test_a_shadow_walk_without_the_grant_reports_no_loop(governance: Any, tmp_path: Path) -> None:
    report, _, _ = governance.shadow(
        governance.manifest(proposal_source="model-driven"),
        tmp_path / "shadow",
        scenarios=[roomy(load_scenario(SCENARIO))],
        attacker=lambda: model_driven(FixedAttackerModel(4)),
    )
    assert report.would_be_loops is None
    assert b"would_be_loops" not in report.canonical_bytes()


def test_an_approved_model_driven_attacker_that_loops_is_stopped(
    governance: Any, tmp_path: Path
) -> None:
    """Shadow, approve, execute -- as WP5.1.6 runs the profile; the executed loop ends the run."""
    requested = governance.manifest(proposal_source="model-driven", loop_guard=GUARD)
    scenario = roomy(load_scenario(SCENARIO))
    report, _, _ = governance.shadow(
        requested,
        tmp_path / "shadow",
        scenarios=[scenario],
        attacker=lambda: model_driven(FixedAttackerModel(4)),
    )
    approval = governance.approve(requested, report)
    manifest = governance.approved(requested, approval)
    model = FixedAttackerModel(4)
    bundle = tmp_path / "execute"
    runner = governance.agent_runner(
        manifest,
        bundle,
        governance.admission([approval], [report]),
        attacker=model_driven(model),
    )
    summary = asyncio.run(runner.run(scenario, manifest, run_id="looping", output_dir=bundle))
    events = runner.runtime.ledger.verify()
    assert summary.reason == RUNAWAY_LOOP_DETECTED
    assert detections(events)[0].stage == "detect"
    assert model.calls == 1
    assert_stopped_at_detection(events)
    verify_bundle(bundle, allow_partial=True)


# --- fault injection: teardown and evidence after a trip -----------------------------------------


@pytest.mark.parametrize("looping_stage", ["clean", "attack"])
def test_a_trip_in_either_leg_stage_still_tears_down_and_seals_evidence(
    tmp_path: Path, looping_stage: str
) -> None:
    """The model loops only in the named stage; teardown, ledger, bundle, and export all hold."""

    class StageLoopingModel(LoopingModel):
        def __init__(self) -> None:
            super().__init__([MAILBOX] * 4)
            self.turn = 0

        async def complete(self, **kwargs: Any) -> tuple[str, int, int]:
            self.turn += 1
            if (self.turn == 1) != (looping_stage == "clean"):
                return json.dumps({"message": "Fine.", "tool_intents": []}), 50, 20
            return await super().complete(**kwargs)

    summary, _, events, lab, bundle = agent_run(tmp_path, model=StageLoopingModel())
    assert summary.reason == RUNAWAY_LOOP_DETECTED
    assert detections(events)[0].stage == looping_stage
    assert summary.teardown_complete and lab.closed
    assert any(e.stage == "teardown" and e.trace_id.startswith("control-") for e in events)
    assert_stopped_at_detection(events)
    verify_bundle(bundle, allow_partial=True)
    export = export_audit(bundle, tmp_path / "audit.json")
    decisions = export["runs"][0]["decisions"]
    kinds = {d["kind"] for d in decisions if d["reason_code"] == RUNAWAY_LOOP_DETECTED}
    assert kinds == {"policy", "termination"}
    assert json.loads((bundle / "summary.json").read_text())["reason"] == RUNAWAY_LOOP_DETECTED


# --- the detector cannot be removed or faked without a test failing ------------------------------


def test_a_removed_detector_fails_the_stop_assertion(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(LoopGuard, "boundary", lambda self, fingerprint, stage: None)
    monkeypatch.setattr(LoopGuard, "observe", lambda self, outcome: None)
    summary, _, events, _, _ = agent_run(tmp_path, model=LoopingModel([MAILBOX] * 4))
    assert summary.reason != RUNAWAY_LOOP_DETECTED
    with pytest.raises(AssertionError):
        assert_stopped_at_detection(events)


def test_a_detector_that_records_but_never_stops_fails_the_stop_assertion(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from purpleloop.runtime.runtime import SafetyRuntime

    original = SafetyRuntime._loop_boundary

    def record_only(self: Any, *args: Any) -> None:
        original(self, *args)  # the detection event is still written ...
        return None  # ... and the action goes ahead anyway

    monkeypatch.setattr(SafetyRuntime, "_loop_boundary", record_only)
    monkeypatch.setattr(LoopGuard, "latch", lambda self, trip: None)
    monkeypatch.setattr(SafetyRuntime, "loop_tripped", property(lambda self: False))
    _, _, events, _, _ = agent_run(tmp_path, model=LoopingModel([MAILBOX] * 4))
    assert detections(events)
    with pytest.raises(AssertionError):
        assert_stopped_at_detection(events)


# --- the legitimate corpus never trips at tight limits -------------------------------------------

TIGHT = LoopGuardGrant(repeat_limit=2, no_progress_limit=4)


def test_an_armed_guard_leaves_every_agent_outcome_at_its_pin(tmp_path: Path) -> None:
    """Every agent-lane scenario, armed at the tightest limits the measured peaks allow.

    Status, verdicts, finding count, and oracle hash must equal ``regression-outcomes.json``.
    """
    from purpleloop.runtime.pinning import load_outcomes, outcome_of, pinned_scenarios

    pins = load_outcomes().by_scenario()
    agent = [p for p in pinned_scenarios() if p.lane == "agent"]
    assert len(agent) == 25
    for pinned in agent:
        summary, runner, _, _, _ = agent_run(
            tmp_path / pinned.scenario_id, guard=TIGHT, scenario=pinned.scenario
        )
        assert outcome_of("agent", summary) == pins[pinned.scenario_id], pinned.scenario_id
        guard = runner.runtime.loop_guard(runner.manifest)
        assert guard.armed and guard.tripped is None
        assert guard.peak_repeats < TIGHT.repeat_limit
        assert guard.peak_streak < TIGHT.no_progress_limit


@pytest.mark.parametrize(
    "scenario_id", ["agent-encoded-injection", "agent-goal-hijack", "agent-tool-misuse"]
)
def test_the_bounded_attacker_on_the_corpus_stays_under_tight_limits(
    tmp_path: Path, scenario_id: str
) -> None:
    from purpleloop.control.phase3_tools import INTENT_OPERATIONS

    attacker = BoundedAttacker(
        max_proposals=8,
        max_depth=3,
        operations=sorted(INTENT_OPERATIONS),
        own_tenant="org-a",
        other_tenants=("org-b",),
        resource_id="admin-a",
    )
    scenario = load_scenario(ROOT / "scenarios" / "agent" / f"{scenario_id}.yaml")
    summary, runner, _, _, _ = agent_run(
        tmp_path, guard=TIGHT, attacker=attacker, scenario=scenario
    )
    assert summary.status == "passed", summary.reason
    assert runner.runtime.loop_guard(runner.manifest).peak_streak < TIGHT.no_progress_limit


# --- kernel: which outcomes count -----------------------------------------------------------------


class DenyAll(PermitAll):
    def evaluate(self, manifest: Any, action: ActionRequest) -> Any:
        from purpleloop.control.policy import PolicyDecision, PolicyEffect

        return PolicyDecision(PolicyEffect.DENY, "OPERATION_NOT_ALLOWED", self.policy_digest)


class FailingAdapter(EchoAdapter):
    async def execute(
        self, action: ActionRequest, *, credential: Any, authorize_target: Any
    ) -> Any:
        raise RuntimeError("the target refused")


def test_policy_denials_change_nothing_and_count_toward_no_progress(tmp_path: Path) -> None:
    runtime, manifest = kernel(tmp_path, LoopGuardGrant(repeat_limit=64, no_progress_limit=3))
    runtime.policy = DenyAll()
    results = submit_all(runtime, manifest, [1, 2, 3, 4])
    assert [r.reason_code for r in results] == ["OPERATION_NOT_ALLOWED"] * 3
    trip = runtime.loop_guard(manifest).tripped
    assert trip is not None and trip.check == "no-progress" and trip.observed == 3


def test_failed_executions_change_nothing_and_count_toward_no_progress(tmp_path: Path) -> None:
    runtime, manifest = kernel(tmp_path, LoopGuardGrant(repeat_limit=64, no_progress_limit=2))
    runtime.adapter = FailingAdapter()
    results = submit_all(runtime, manifest, [1, 2, 3])
    assert [r.status for r in results] == ["failed", "failed"]
    assert runtime.loop_tripped


def test_a_stopped_kernel_is_not_a_loop(tmp_path: Path) -> None:
    runtime, manifest = kernel(tmp_path, LoopGuardGrant(repeat_limit=2, no_progress_limit=1))
    asyncio.run(runtime.kill_switch.terminate())
    results = submit_all(runtime, manifest, [1, 2, 3])
    assert {r.reason_code for r in results} == {"KERNEL_STOPPED"}
    assert not runtime.loop_tripped


def test_refused_steps_latch_in_execute_and_only_report_in_shadow(tmp_path: Path) -> None:
    grant = LoopGuardGrant(repeat_limit=2, no_progress_limit=64)
    runtime, manifest = kernel(tmp_path / "execute", grant)
    assert not runtime.refused_step(manifest, step(), "R", run_id="p", trace_id="t")
    assert runtime.refused_step(manifest, step(node_id="n-2"), "R", run_id="p", trace_id="t")
    # Latched: every later refusal, of anything, ends the run too.
    assert runtime.refused_step(manifest, "other.op", "R", run_id="p", trace_id="t")

    runtime, manifest = kernel(tmp_path / "shadow", grant)
    runtime.shadow = True
    for _ in range(3):
        assert not runtime.refused_step(manifest, step(), "R", run_id="p", trace_id="t")
    assert not runtime.loop_tripped
    flagged = [e for e in runtime.ledger.verify() if e.reason_code == RUNAWAY_LOOP_WOULD_TRIP]
    assert len(flagged) == 1 and flagged[0].decision == "would-deny"

    disarmed, _ = kernel(tmp_path / "off", grant)
    unguarded = agent_manifest_15(Ed25519PrivateKey.generate())
    assert not disarmed.refused_step(unguarded, step(), "R", run_id="p", trace_id="t")
