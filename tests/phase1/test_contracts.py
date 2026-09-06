from __future__ import annotations

from typing import Any

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from pydantic import ValidationError

from purpleloop.adapters.phase1 import AdapterRegistry, HttpAdapter
from purpleloop.control.phase1_tools import PHASE1_TOOLS
from purpleloop.control.plan_compiler import PlanError, compile_plan, compile_step
from purpleloop.control.policy import DefaultDenyPolicy
from purpleloop.control.tools import ToolDefinitionError
from purpleloop.schemas.action import ActionRequest, SideEffectClass
from purpleloop.schemas.authorization import AuthorizationManifest
from purpleloop.schemas.phase1 import OracleSpec, Phase1Scenario
from purpleloop.scoring.phase1 import detect, detection_metrics, evaluate


def test_schema_policy_and_plan_validation(scenarios: Any, phase1_manifest: Any) -> None:
    scenario = scenarios[0]
    plan = compile_plan(scenario, phase1_manifest)
    assert plan.manifest_digest == phase1_manifest.manifest_digest()
    cases = [
        scenario.model_copy(update={"attack_steps": (scenario.clean_steps[0],)}),
        scenario.model_copy(
            update={
                "attack_steps": (
                    scenario.attack_steps[0].model_copy(update={"depends_on": ("missing",)}),
                )
            }
        ),
        scenario.model_copy(
            update={
                "attack_steps": (
                    scenario.attack_steps[0].model_copy(update={"depends_on": ("attack-read",)}),
                )
            }
        ),
        scenario.model_copy(
            update={
                "attack_steps": (
                    scenario.attack_steps[0].model_copy(update={"depends_on": ("clean-read",)}),
                )
            }
        ),
        scenario.model_copy(update={"actor": scenario.actor.model_copy(update={"role": "admin"})}),
        scenario.model_copy(update={"authorization_digest": "a" * 64}),
        scenario.model_copy(update={"defense_profile": "unknown"}),
        scenario.model_copy(update={"clean_steps": ()}),
    ]
    for invalid in cases:
        with pytest.raises(ValueError):
            compile_plan(invalid, phase1_manifest)
    for fields in ({"max_nodes": 1}, {"max_depth": 1}):
        limited = phase1_manifest.model_copy(
            update={"phase1": phase1_manifest.phase1.model_copy(update=fields)}
        )
        with pytest.raises(PlanError):
            compile_plan(
                next(s for s in scenarios if s.scenario_id == "indirect-injection"), limited
            )
    with pytest.raises(ValidationError):
        Phase1Scenario.model_validate({**scenario.model_dump(), "shell": "anything"})
    with pytest.raises(ValidationError):
        ActionRequest.model_validate(
            {**plan.nodes[0].action.model_dump(), "side_effect": "destructive"}
        )
    with pytest.raises(ValidationError):
        AuthorizationManifest.model_validate(
            {**phase1_manifest.model_dump(), "schema_version": "1.0.0"}
        )
    with pytest.raises(ValidationError):
        AuthorizationManifest.model_validate(
            {**phase1_manifest.model_dump(), "allowed_side_effects": ["destructive"]}
        )
    with pytest.raises(ValidationError):
        AuthorizationManifest.model_validate(
            {**phase1_manifest.model_dump(), "schema_version": "2.0.0"}
        )


def test_registry_and_typed_arguments(scenarios: Any, phase1_manifest: Any) -> None:
    scenario = next(s for s in scenarios if s.scenario_id == "mass-assignment")
    action = compile_step(scenario.attack_steps[0], scenario, phase1_manifest)
    registry = AdapterRegistry((("tool", "record.update", HttpAdapter()),))
    assert registry.require(action)
    with pytest.raises(ValueError):
        AdapterRegistry(
            (("tool", "record.update", HttpAdapter()), ("tool", "record.update", HttpAdapter()))
        )
    with pytest.raises(ToolDefinitionError):
        PHASE1_TOOLS.lookup("unknown", "unknown")
    for mutation in (
        {"arguments": {"shell": "id"}},
        {"arguments": {"tier": "root"}},
        {"method": "POST"},
        {"credential_handle": None},
        {"schema_version": None},
        {"budget": action.budget.model_copy(update={"writes": 0})},
    ):
        decision = DefaultDenyPolicy(PHASE1_TOOLS).evaluate(
            phase1_manifest, action.model_copy(update=mutation)
        )
        assert not decision.permitted


@given(
    st.sampled_from(["host", "tenant", "resource", "method", "arguments", "effect", "credential"])
)
@settings(max_examples=14)
def test_scope_mutations_fail_before_io(kind: str) -> None:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from purpleloop.runtime.demo import ROOT, demo_manifest
    from purpleloop.schemas.phase1 import load_scenario

    scenario = load_scenario(ROOT / "scenarios/phase1/mass-assignment.yaml")
    manifest = demo_manifest(Ed25519PrivateKey.generate())
    action = compile_step(scenario.attack_steps[0], scenario, manifest)
    changes = {
        "host": {
            "target": action.target.model_copy(
                update={"url": "http://example.invalid:18080/records/record-a"}
            )
        },
        "tenant": {"target": action.target.model_copy(update={"tenant_id": "outsider"})},
        "resource": {"target": action.target.model_copy(update={"resource_id": "different"})},
        "method": {"method": "DELETE"},
        "arguments": {"arguments": {"unknown": True}},
        "effect": {"side_effect": SideEffectClass.DESTRUCTIVE},
        "credential": {"credential_handle": "fixture-control"},
    }
    assert (
        not DefaultDenyPolicy(PHASE1_TOOLS)
        .evaluate(manifest, action.model_copy(update=changes[kind]))
        .permitted
    )


@pytest.mark.parametrize(
    "operator,path,expected,comparison,verdict",
    [
        ("equals", ("x",), 1, "eq", "true"),
        ("equals", ("x",), 2, "eq", "false"),
        ("exists", ("missing",), None, "eq", "false"),
        ("exists", ("x",), None, "eq", "true"),
        ("contains", ("items",), "a", "eq", "true"),
        ("contains", ("x",), "a", "eq", "inconclusive"),
        ("contains", ("mapping",), [], "eq", "inconclusive"),
        ("count", ("items",), 1, "eq", "true"),
        ("count", ("items",), 0, "gt", "true"),
        ("count", ("x",), 2, "eq", "inconclusive"),
        ("delta", ("x",), None, "eq", "true"),
        ("delta", ("same",), None, "eq", "false"),
        ("equals", ("items", 4), None, "eq", "false"),
    ],
)
def test_oracle_operators(
    operator: Any, path: Any, expected: Any, comparison: Any, verdict: str
) -> None:
    result = evaluate(
        OracleSpec(operator=operator, path=path, expected=expected, comparison=comparison),
        before={"x": 0, "same": 1},
        state={"x": 1, "same": 1, "items": ["a"], "mapping": {}},
        responses=[],
        telemetry=[],
        evidence_ids=("evidence",),
    )
    assert result.verdict == verdict


def test_detector_metrics() -> None:
    results = detect([{"rule_id": "unexpected", "tick": 3}], ("expected",), "event", 1)
    metrics = detection_metrics(results)
    assert metrics["false_positives"] == metrics["false_negatives"] == 1
    assert results[1].time_to_detect == 2


async def test_allowed_tenant_cannot_be_substituted_for_resource_owner(
    make_runner: Any, scenarios: Any, phase1_manifest: Any
) -> None:
    scenario = scenarios[0]
    action = compile_step(scenario.attack_steps[0], scenario, phase1_manifest)
    # Both tenants are signed scope, but record-b belongs only to tenant-b.
    mutated = action.model_copy(
        update={"target": action.target.model_copy(update={"tenant_id": "tenant-a"})}
    )
    runner, fixture, _ = make_runner()
    result = await runner.runtime.run(
        phase1_manifest, mutated, run_id="tenant-mismatch", trace_id="tenant-mismatch"
    )
    assert result.status == "denied"
    assert not fixture.state.audit
    assert runner.runtime.budgets.used.requests == 0
