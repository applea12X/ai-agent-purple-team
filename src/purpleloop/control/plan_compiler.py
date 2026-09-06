from __future__ import annotations

from typing import Literal

from purpleloop.control.phase1_tools import PHASE1_TOOLS
from purpleloop.control.policy import DefaultDenyPolicy
from purpleloop.schemas.action import ActionRequest, ActionTarget, BudgetRequest, SideEffectClass
from purpleloop.schemas.authorization import AuthorizationManifest
from purpleloop.schemas.phase1 import ExecutionPlan, Phase1Scenario, PlanNode, Step


class PlanError(ValueError):
    pass


def compile_step(
    step: Step, scenario: Phase1Scenario, manifest: AuthorizationManifest
) -> ActionRequest:
    definition = PHASE1_TOOLS.lookup(step.adapter, step.operation)
    assets = [asset for asset in manifest.assets if asset.asset_id == step.asset_id]
    if len(assets) != 1 or step.target_tenant not in assets[0].tenant_ids:
        raise PlanError("unknown asset or unauthorized target tenant")
    asset = assets[0]
    if step.target_tenant != scenario.actor.tenant_id and step.operation != "record.read":
        raise PlanError("cross-tenant action is not a registered fixture exercise")
    path = definition.path_template.format(resource_id=step.resource_id or "")
    action = ActionRequest(
        schema_version="1.1.0",
        action_id=step.node_id,
        adapter=step.adapter,
        operation=step.operation,
        method=definition.method,
        target=ActionTarget(
            url=f"{asset.scheme}://{asset.host}:{asset.port}{path}",
            tenant_id=step.target_tenant,
            resource_id=step.resource_id,
        ),
        side_effect=definition.side_effect,
        credential_handle=scenario.actor.credential_handle,
        idempotency_key=f"{scenario.scenario_id}:{step.node_id}",
        arguments=step.arguments,
        budget=BudgetRequest(
            requests=1,
            writes=int(definition.side_effect == SideEffectClass.WRITE),
            records=definition.min_records,
            tokens=definition.min_tokens,
        ),
    )
    decision = DefaultDenyPolicy(PHASE1_TOOLS).evaluate(manifest, action)
    if not decision.permitted:
        raise PlanError(decision.reason_code)
    return action


def compile_plan(scenario: Phase1Scenario, manifest: AuthorizationManifest) -> ExecutionPlan:
    scenario.require_runnable()
    if (
        scenario.actor.actor_id,
        scenario.actor.role,
        scenario.actor.tenant_id,
        scenario.actor.credential_handle,
    ) != ("customer-a", "customer", "tenant-a", "fixture-customer"):
        raise PlanError("actor does not match the trusted fixture credential binding")
    if manifest.schema_version != "1.1.0" or manifest.phase1 is None:
        raise PlanError("Phase 1 manifest required")
    expected_assets = {"fixture-data": 18080, "fixture-control": 18081}
    if len(manifest.assets) != 2 or any(
        expected_assets.get(asset.asset_id) != asset.port for asset in manifest.assets
    ):
        raise PlanError("manifest must bind the managed Phase 1 fixture listeners")
    if scenario.authorization_digest not in {None, manifest.manifest_digest()}:
        raise PlanError("scenario manifest digest mismatch")
    if scenario.defense_profile not in manifest.phase1.defense_profiles:
        raise PlanError("defense not pre-authorized")
    tagged: list[tuple[Literal["clean", "attack"], Step]] = [
        ("clean", s) for s in scenario.clean_steps
    ] + [("attack", s) for s in scenario.attack_steps]
    ids = [s.node_id for _, s in tagged]
    intent_slots = sum(s.adapter == "chat" for _, s in tagged)
    if len(set(ids)) != len(ids) or len(ids) + intent_slots > manifest.phase1.max_nodes:
        raise PlanError("duplicate nodes or graph exceeds signed limit")
    pending = {s.node_id: (stage, s) for stage, s in tagged}
    depths: dict[str, int] = {}
    nodes: list[PlanNode] = []
    while pending:
        ready = sorted(
            key for key, (_, s) in pending.items() if all(d in depths for d in s.depends_on)
        )
        if not ready:
            raise PlanError("cycle or missing dependency")
        for key in ready:
            stage, step = pending.pop(key)
            if any(next(t for t, s in tagged if s.node_id == d) != stage for d in step.depends_on):
                raise PlanError("dependencies cannot cross execution legs")
            depths[key] = 1 + max((depths[d] for d in step.depends_on), default=0)
            if depths[key] + int(step.adapter == "chat") > manifest.phase1.max_depth:
                raise PlanError("graph exceeds signed depth")
            nodes.append(
                PlanNode(
                    node_id=key,
                    stage=stage,
                    action=compile_step(step, scenario, manifest),
                    depends_on=step.depends_on,
                )
            )
    return ExecutionPlan(
        scenario_id=scenario.scenario_id,
        scenario_digest=scenario.digest(),
        manifest_digest=manifest.manifest_digest(),
        nodes=tuple(nodes),
    )
