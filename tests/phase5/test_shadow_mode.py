"""Shadow mode (WP5.1.2-5.1.3): every action is decided, none is dispatched.

The checkpoint is "0 adapter calls", measured three ways at once: the runner's own
``CountingAdapter`` around the runtime's adapter, a counting transport in front of the
in-process fixture, and a counting wrapper around the target model. Every corpus of every lane
is shadowed with its real adapters, and fault-injection cases try to force execution through
each registered adapter and operation.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from pydantic import ValidationError

from purpleloop.control import phase2_tools, phase3_tools
from purpleloop.control.budgets import BudgetLedger
from purpleloop.control.credentials import InMemoryCredentialBroker
from purpleloop.control.kill_switch import KillSwitch
from purpleloop.control.lanes import AGENT_LANE, PHASE1_LANE, SUPPORTLAB_LANE, LaneContract
from purpleloop.control.manifest import ManifestVerifier
from purpleloop.control.phase1_tools import PHASE1_TOOLS
from purpleloop.control.policy import PolicyDecision, PolicyEffect
from purpleloop.control.redaction import Redactor
from purpleloop.control.tools import PHASE0_TOOLS, ToolRegistry
from purpleloop.reporting.bundle import inventory
from purpleloop.reporting.gates import scope_gate
from purpleloop.runtime.demo import InProcessFixture, build_runner, demo_manifest
from purpleloop.runtime.ledger import EvidenceLedger
from purpleloop.runtime.runtime import SafetyRuntime
from purpleloop.runtime.shadow import (
    CountingAdapter,
    ShadowBundleError,
    ShadowRunner,
    build_shadow_report,
    verify_shadow_bundle,
)
from purpleloop.runtime.supportlab import (
    KEY_ID,
    InProcessSupportlab,
    actor_credentials,
    build_supportlab_runner,
    supportlab_manifest,
)
from purpleloop.schemas.action import ActionRequest, ActionTarget, BudgetRequest
from purpleloop.schemas.authorization import AuthorizationManifest
from purpleloop.schemas.event import EventKind, EvidenceEvent
from purpleloop.schemas.phase1 import Phase1Scenario, load_scenario, scenario_paths

ROOT = Path(__file__).parents[2]
Counts = dict[str, int]


def corpus(lane: str) -> list[Phase1Scenario]:
    return [load_scenario(path) for path in scenario_paths(ROOT / "scenarios" / lane)]


def ledgers(bundle: Path) -> dict[str, list[EvidenceEvent]]:
    index = json.loads((bundle / "shadow.json").read_text())
    return {
        sid: EvidenceLedger(bundle / sid / "evidence.jsonl").verify() for sid in index["scenarios"]
    }


def expected_unreachable(scenarios: list[Phase1Scenario], lane: LaneContract, intents: int) -> int:
    """Independently of the runner: intent slots per model turn, per pass that runs it."""
    total = 0
    for scenario in scenarios:
        clean_turns = sum(step.adapter in {"chat", "agent"} for step in scenario.clean_steps)
        attack_turns = sum(step.adapter in {"chat", "agent"} for step in scenario.attack_steps)
        clean_passes = 2 if lane.requires_phase3 and scenario.utility_oracle is not None else 1
        for steps, passes in ((scenario.clean_steps, clean_passes), (scenario.attack_steps, 1)):
            for step in steps:
                if step.adapter in {"chat", "agent"}:
                    total += passes * 2 * (1 if step.adapter == "chat" else intents)
        assert clean_turns + attack_turns >= 0
    return total


def assert_nothing_executed(bundle: Path, runner: ShadowRunner, counts: Counts) -> None:
    assert counts.get("fixture-requests", 0) == 0
    assert counts.get("model-calls", 0) == 0
    assert runner.counters and all(c.dispatches == 0 for c in runner.counters.values())
    for events in ledgers(bundle).values():
        assert not any(event.kind == EventKind.RESULT for event in events)
        terminated = [e for e in events if e.reason_code == "SHADOW_TERMINATED"]
        assert terminated and terminated[0].data["reason"] == "SHADOW_COMPLETE"
        calls = [e for e in events if e.reason_code == "SHADOW_ADAPTER_CALLS"]
        assert [e.data["dispatches"] for e in calls] == [0]
    all_events = [event for events in ledgers(bundle).values() for event in events]
    decision = scope_gate(all_events)
    assert not decision.blocked and decision.detail.startswith("0 executed results")


# --- the full corpora, real adapters ------------------------------------------------------------


def test_the_full_agent_corpus_in_shadow_dispatches_nothing(
    governance: Any, tmp_path: Path
) -> None:
    scenarios = corpus("agent")
    assert len(scenarios) == 25
    report, runner, twin = governance.shadow(
        governance.manifest(), tmp_path, scenarios=scenarios, attacker=governance.attacker
    )
    assert_nothing_executed(tmp_path, runner, governance.counts)
    assert report.adapter_calls == 0
    assert verify_shadow_bundle(tmp_path) == report
    suppressed = sum(
        e.kind == EventKind.SHADOW_SUPPRESSED
        for events in ledgers(tmp_path).values()
        for e in events
    )
    assert report.suppressed_executions == suppressed > 0
    assert len(report.scenario_digests) == 25
    assert report.unreachable_steps == expected_unreachable(scenarios, AGENT_LANE, 4)
    assert report.proposals_total > 0
    assert report.manifest_digest == twin.manifest_digest()


def test_the_full_agent_corpus_with_the_model_driven_attacker_dispatches_nothing(
    governance: Any, tmp_path: Path
) -> None:
    from purpleloop.adapters.scripted_attacker import ScriptedAttackerModel

    models: list[ScriptedAttackerModel] = []

    def attacker() -> Any:
        models.append(ScriptedAttackerModel())
        return governance.attacker("model-driven", model=models[-1])

    report, runner, _ = governance.shadow(
        governance.manifest(proposal_source="model-driven"),
        tmp_path,
        scenarios=corpus("agent"),
        attacker=attacker,
    )
    assert_nothing_executed(tmp_path, runner, governance.counts)
    # The attacker model is the harness's proposal source, not a target adapter: it is consulted
    # in shadow (that is the point), and every call is evidence; nothing it proposes executes.
    recorded = sum(
        e.reason_code == "ATTACKER_MODEL_CALLED"
        for events in ledgers(tmp_path).values()
        for e in events
    )
    assert sum(model.calls for model in models) == recorded >= 25 * 2
    assert report.proposals_total > report.proposals_rejected > 0
    assert report.denials_by_reason["PROPOSAL_UNKNOWN_OPERATION"] == 50


def _shadow_legacy(
    lane: LaneContract,
    scenarios: list[Phase1Scenario],
    manifest: AuthorizationManifest,
    key: Ed25519PrivateKey,
    factory: Callable[[Path], SafetyRuntime],
    out: Path,
) -> tuple[Any, ShadowRunner]:
    runner = ShadowRunner(factory, lane=lane)
    report = asyncio.run(
        runner.run(
            scenarios,
            manifest,
            run_id="shadow-legacy",
            output_dir=out,
            public_key_pem=key.public_key().public_bytes(
                Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
            ),
        )
    )
    return report, runner


def test_legacy_lanes_shadow_through_every_real_adapter(
    tmp_path: Path, counting_transport: Any
) -> None:
    """Phase 1 and supportlab corpora, with v1 manifests, shadowed by the runtime flag alone."""
    counts: dict[str, int] = {"fixture-requests": 0}
    key = Ed25519PrivateKey.generate()

    manifest_11 = demo_manifest(key)
    verifier_11 = ManifestVerifier({"demo-key": key.public_key()})

    def phase1_runtime(directory: Path) -> SafetyRuntime:
        customer, control = "c" * 48, "d" * 48
        fixture = InProcessFixture(customer, control)
        fixture.transports = {
            port: counting_transport(transport, counts)
            for port, transport in fixture.transports.items()
        }
        return build_runner(
            directory, manifest_11, verifier_11, customer=customer, control=control, fixture=fixture
        ).runtime

    manifest_12 = supportlab_manifest(key)
    verifier_12 = ManifestVerifier({KEY_ID: key.public_key()})

    def supportlab_runtime(directory: Path) -> SafetyRuntime:
        tokens = actor_credentials()
        control = actor_credentials()["customer-a"]
        fixture = InProcessSupportlab(tokens, control)
        fixture.transports = {
            port: counting_transport(transport, counts)
            for port, transport in fixture.transports.items()
        }
        return build_supportlab_runner(
            directory,
            manifest_12,
            verifier_12,
            actor_tokens=tokens,
            control=control,
            fixture=fixture,
        ).runtime

    adapters_reached: set[str] = set()
    for lane, scenarios, manifest, factory in (
        (PHASE1_LANE, corpus("phase1"), manifest_11, phase1_runtime),
        (SUPPORTLAB_LANE, corpus("supportlab"), manifest_12, supportlab_runtime),
    ):
        out = tmp_path / lane.name
        report, runner = _shadow_legacy(lane, scenarios, manifest, key, factory, out)
        assert_nothing_executed(out, runner, counts)
        assert report.adapter_calls == 0 and report.suppressed_executions > 0
        assert verify_shadow_bundle(out) == report
        adapters_reached |= {
            str(e.data["adapter"])
            for events in ledgers(out).values()
            for e in events
            if e.kind == EventKind.SHADOW_SUPPRESSED
        }
    # Together with the agent corpus (agent, http, control), every adapter kind is decided.
    assert {"http", "tool", "chat", "browser", "control"} <= adapters_reached


# --- fault injection: try to force execution through every adapter -------------------------------


class ExplodingAdapter:
    """An adapter that fails the test the moment anything reaches it."""

    name = "exploding"

    def __init__(self) -> None:
        self.touched: list[str] = []

    async def preflight(self, action: ActionRequest) -> None:
        self.touched.append(f"preflight:{action.adapter}:{action.operation}")
        raise AssertionError("shadow dispatched a preflight")

    async def execute(self, action: ActionRequest, **_: Any) -> Any:
        self.touched.append(f"execute:{action.adapter}:{action.operation}")
        raise AssertionError("shadow dispatched an execution")

    async def cancel(self) -> None:
        self.touched.append("cancel")

    async def postcondition(self, action: ActionRequest, result: Any) -> bool:
        self.touched.append("postcondition")
        raise AssertionError("shadow dispatched a postcondition")


class PermitEverything:
    """A policy that permits anything, so a shadow decision is the only thing in the way."""

    policy_digest = "0" * 64

    def evaluate(self, manifest: AuthorizationManifest, action: ActionRequest) -> PolicyDecision:
        return PolicyDecision(PolicyEffect.PERMIT, "PERMITTED", self.policy_digest)


class TrustEverything:
    def verify(self, manifest: AuthorizationManifest, *, now: datetime | None = None) -> Any:
        return manifest


REGISTRIES: dict[str, ToolRegistry] = {
    "phase0": PHASE0_TOOLS,
    "phase1": PHASE1_TOOLS,
    "supportlab": phase2_tools.SUPPORTLAB_TOOLS,
    "agent": phase3_tools.SUPPORTLAB_AGENT_TOOLS,
}
OPERATIONS = sorted(
    {
        (name, adapter, operation)
        for name, registry in REGISTRIES.items()
        for (adapter, operation) in registry._definitions  # noqa: SLF001 -- test enumeration
    }
)


def action_for(registry: ToolRegistry, adapter: str, operation: str, index: int) -> ActionRequest:
    definition = registry.lookup(adapter, operation)
    return ActionRequest(
        schema_version="1.1.0",
        action_id=f"inject-{index}",
        adapter=adapter,
        operation=operation,
        method=definition.method,
        target=ActionTarget(
            url=f"http://127.0.0.1:1{definition.path_template.format(resource_id='r-1')}",
            tenant_id="org-a",
            resource_id="r-1" if definition.resource_required else None,
        ),
        side_effect=definition.side_effect,
        credential_handle="injected",
        idempotency_key=f"inject-{index}",
        arguments={},
        budget=BudgetRequest(requests=1, records=1),
    )


def shadow_runtime(
    tmp_path: Path, manifest: AuthorizationManifest, *, flag: bool, admission: Any = None
) -> tuple[SafetyRuntime, ExplodingAdapter, CountingAdapter]:
    exploding = ExplodingAdapter()
    counter = CountingAdapter(exploding)
    runtime = SafetyRuntime(
        verifier=TrustEverything(),  # type: ignore[arg-type]
        policy=PermitEverything(),
        budgets=BudgetLedger(
            manifest.budgets.model_copy(update={"requests": 10_000, "records": 10_000})
        ),
        kill_switch=KillSwitch(),
        credential_broker=InMemoryCredentialBroker({"injected": "secret-value"}),
        redactor=Redactor(("secret-value",)),
        adapter=counter,
        ledger=EvidenceLedger(tmp_path / "evidence.jsonl"),
        shadow=flag,
        admission=admission,
    )
    return runtime, exploding, counter


@pytest.mark.parametrize("path", ["runtime-flag", "shadow-manifest", "both"])
def test_every_registered_operation_is_suppressed_never_dispatched(
    governance: Any, tmp_path: Path, path: str
) -> None:
    """Every (adapter, operation) in every lane registry, with a policy that permits all of it."""
    if path == "runtime-flag":
        manifest = supportlab_manifest(Ed25519PrivateKey.generate())
        runtime, exploding, counter = shadow_runtime(tmp_path, manifest, flag=True)
    else:
        manifest = governance.manifest(run_mode="shadow")
        runtime, exploding, counter = shadow_runtime(
            tmp_path, manifest, flag=path == "both", admission=governance.admission()
        )
    for index, (name, adapter, operation) in enumerate(OPERATIONS):
        action = action_for(REGISTRIES[name], adapter, operation, index)
        result = asyncio.run(runtime.run(manifest, action, run_id="inject", trace_id=f"t{index}"))
        assert (result.status, result.reason_code) == ("suppressed", "SHADOW_SUPPRESSED"), action
    assert exploding.touched == [] and counter.dispatches == 0
    adapters = {adapter for _, adapter, _ in OPERATIONS}
    assert {"mock_read", "http", "tool", "chat", "browser", "control", "agent"} <= adapters
    events = runtime.ledger.verify()
    suppressed = [e for e in events if e.kind == EventKind.SHADOW_SUPPRESSED]
    assert len(suppressed) == len(OPERATIONS)
    assert all(e.schema_version == "1.2.0" and e.decision == "suppressed" for e in suppressed)
    # The credential was never resolved, so it can appear nowhere.
    assert "secret-value" not in (tmp_path / "evidence.jsonl").read_text()


def test_an_execute_manifest_cannot_take_a_shadow_runtime_out_of_shadow(
    governance: Any, tmp_path: Path
) -> None:
    manifest = governance.manifest(run_mode="execute")
    runtime, exploding, _ = shadow_runtime(
        tmp_path, manifest, flag=True, admission=governance.admission()
    )
    action = action_for(PHASE1_TOOLS, *sorted(PHASE1_TOOLS._definitions)[0], 0)  # noqa: SLF001
    result = asyncio.run(runtime.run(manifest, action, run_id="r", trace_id="t"))
    assert result.status == "suppressed" and exploding.touched == []


def test_concurrent_shadow_actions_dispatch_nothing(governance: Any, tmp_path: Path) -> None:
    manifest = governance.manifest(run_mode="shadow")
    runtime, exploding, counter = shadow_runtime(
        tmp_path, manifest, flag=False, admission=governance.admission()
    )
    runtime.budgets = BudgetLedger(
        manifest.budgets.model_copy(
            update={"concurrency": 64, "requests": 10_000, "records": 10_000}
        )
    )

    async def many() -> list[Any]:
        return await asyncio.gather(
            *(
                runtime.run(
                    manifest,
                    action_for(REGISTRIES[name], adapter, operation, index),
                    run_id="concurrent",
                    trace_id=f"t{index}",
                )
                for index, (name, adapter, operation) in enumerate(OPERATIONS)
            )
        )

    results = asyncio.run(many())
    assert {result.status for result in results} == {"suppressed"}
    assert exploding.touched == [] and counter.dispatches == 0


def test_a_stopped_kernel_or_an_exhausted_budget_denies_in_shadow_too(
    governance: Any, tmp_path: Path
) -> None:
    manifest = governance.manifest(run_mode="shadow")
    runtime, exploding, _ = shadow_runtime(
        tmp_path, manifest, flag=False, admission=governance.admission()
    )
    action = action_for(PHASE1_TOOLS, *sorted(PHASE1_TOOLS._definitions)[0], 0)  # noqa: SLF001
    runtime.budgets = BudgetLedger(manifest.budgets.model_copy(update={"requests": 1}))
    first = asyncio.run(runtime.run(manifest, action, run_id="r", trace_id="1"))
    second = asyncio.run(runtime.run(manifest, action, run_id="r", trace_id="2"))
    # Shadow consumes the reservation, so the budget runs out exactly where execution's would.
    assert (first.status, second.status, second.reason_code) == (
        "suppressed",
        "denied",
        "BUDGET_EXCEEDED",
    )
    asyncio.run(runtime.kill_switch.pause())
    stopped = asyncio.run(runtime.run(manifest, action, run_id="r", trace_id="3"))
    assert (stopped.status, stopped.reason_code) == ("denied", "KERNEL_STOPPED")
    assert exploding.touched == []


def test_the_execute_runner_on_a_shadow_manifest_dispatches_nothing(
    governance: Any, tmp_path: Path
) -> None:
    """Fault injection at the runner: the paired runner, not the shadow runner, is handed a
    shadow manifest. The kernel still dispatches nothing; the run fails closed."""
    manifest = governance.manifest(run_mode="shadow")
    runner = governance.agent_runner(manifest, tmp_path, governance.admission())
    counter = CountingAdapter(runner.runtime.adapter)
    runner.runtime.adapter = counter
    summary = asyncio.run(
        runner.run(corpus("agent")[0], manifest, run_id="forced", output_dir=tmp_path)
    )
    assert summary.status == "error"
    assert counter.dispatches == 0
    assert governance.counts.get("fixture-requests", 0) == 0


@settings(
    max_examples=25,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow, HealthCheck.function_scoped_fixture],
)
@given(st.lists(st.sampled_from(OPERATIONS), min_size=1, max_size=30))
def test_a_shadow_run_over_generated_plans_never_dispatches(
    tmp_path_factory: pytest.TempPathFactory, plan: list[tuple[str, str, str]]
) -> None:
    manifest = supportlab_manifest(Ed25519PrivateKey.generate())
    runtime, exploding, counter = shadow_runtime(
        tmp_path_factory.mktemp("generated"), manifest, flag=True
    )
    for index, (name, adapter, operation) in enumerate(plan):
        asyncio.run(
            runtime.run(
                manifest,
                action_for(REGISTRIES[name], adapter, operation, index),
                run_id="generated",
                trace_id=f"t{index}",
            )
        )
    assert exploding.touched == [] and counter.dispatches == 0


# --- the report: derived, verified, and unfakeable ------------------------------------------------


def test_a_shadow_that_dispatched_cannot_produce_a_report(
    governance: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Fake the shadow (the runtime silently executes) and the measured count catches it."""
    monkeypatch.setattr(SafetyRuntime, "is_shadow", lambda self, manifest: False)
    with pytest.raises(ValidationError, match="adapter_calls"):
        governance.shadow(governance.manifest(), tmp_path, scenarios=corpus("agent")[:1])
    assert governance.counts["fixture-requests"] > 0


def test_an_unmeasured_dispatch_count_fails_closed(governance: Any) -> None:
    manifest = governance.manifest(run_mode="shadow")
    event = EvidenceEvent(
        schema_version="1.2.0",
        run_id="r",
        trace_id="t",
        sequence=0,
        timestamp=datetime.now(UTC),
        actor="shadow-runner",
        kind=EventKind.LIFECYCLE,
        manifest_digest=manifest.manifest_digest(),
        policy_digest="0" * 64,
        reason_code="SHADOW_ADAPTER_CALLS",
        data={"dispatches": -1},
    )
    with pytest.raises(ValidationError):
        build_shadow_report(
            {"s": [event]}, run_id="r", manifest=manifest, created_at=datetime.now(UTC)
        )


def test_the_report_cannot_be_edited_without_its_ledger(governance: Any, tmp_path: Path) -> None:
    report, _, _ = governance.shadow(
        governance.manifest(), tmp_path, scenarios=corpus("agent")[:1], attacker=governance.attacker
    )
    path = tmp_path / "shadow-report.json"
    edited = json.loads(path.read_text())
    edited["unreachable_steps"] = 0
    path.write_text(json.dumps(edited))
    inventory(tmp_path, complete=True)
    with pytest.raises(ShadowBundleError, match="disagrees"):
        verify_shadow_bundle(tmp_path)
    # And a ledger edit breaks the chain before the report is even compared.
    path.write_text(json.dumps(report.model_dump(mode="json", exclude_none=True)))
    sid = report and json.loads((tmp_path / "shadow.json").read_text())["scenarios"][0]
    ledger = tmp_path / sid / "evidence.jsonl"
    lines = ledger.read_text().splitlines()
    ledger.write_text("\n".join(lines[:-1]) + "\n")
    inventory(tmp_path, complete=True)
    with pytest.raises(Exception, match="anchor|ledger"):
        verify_shadow_bundle(tmp_path)


def test_an_uninventoried_or_incomplete_bundle_is_refused(governance: Any, tmp_path: Path) -> None:
    governance.shadow(governance.manifest(), tmp_path, scenarios=corpus("agent")[:1])
    (tmp_path / "extra.txt").write_text("planted")
    with pytest.raises(ShadowBundleError, match="inventory"):
        verify_shadow_bundle(tmp_path)
    with pytest.raises(ShadowBundleError):
        verify_shadow_bundle(tmp_path / "missing")


def test_shadow_events_are_additive(governance: Any, tmp_path: Path) -> None:
    """Earlier event kinds keep their values; shadow events carry their own schema version."""
    assert [kind.value for kind in EventKind][:13] == [
        "lifecycle",
        "oracle",
        "detector",
        "defense",
        "admission",
        "policy",
        "budget",
        "adapter",
        "result",
        "termination",
        "model",
        "judge",
        "proposal",
    ]
    assert EventKind.SHADOW_SUPPRESSED.value == "shadow-suppressed"
    governance.shadow(governance.manifest(), tmp_path, scenarios=corpus("agent")[:1])
    for events in ledgers(tmp_path).values():
        for event in events:
            if event.kind == EventKind.SHADOW_SUPPRESSED or event.actor == "shadow-runner":
                assert event.schema_version == "1.2.0"
