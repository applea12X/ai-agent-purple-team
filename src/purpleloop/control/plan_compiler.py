from __future__ import annotations

from typing import Literal

from purpleloop.control.lanes import PHASE1_LANE, LaneContract
from purpleloop.control.phase2_tools import FORBIDDEN_BROWSER_KEYS
from purpleloop.control.phase3_tools import INTENT_OPERATIONS
from purpleloop.control.policy import DefaultDenyPolicy
from purpleloop.schemas.action import ActionRequest, ActionTarget, BudgetRequest, SideEffectClass
from purpleloop.schemas.authorization import AuthorizationManifest
from purpleloop.schemas.phase1 import ExecutionPlan, Phase1Scenario, PlanNode, Step
from purpleloop.schemas.phase2 import BrowserStep


class PlanError(ValueError):
    pass


def compile_step(
    step: Step,
    scenario: Phase1Scenario,
    manifest: AuthorizationManifest,
    *,
    lane: LaneContract = PHASE1_LANE,
) -> ActionRequest:
    definition = lane.tools.lookup(step.adapter, step.operation)
    assets = [asset for asset in manifest.assets if asset.asset_id == step.asset_id]
    if len(assets) != 1 or step.target_tenant not in assets[0].tenant_ids:
        raise PlanError("unknown asset or unauthorized target tenant")
    asset = assets[0]
    actor = lane.actors.get(scenario.actor.actor_id)
    if actor is None:
        raise PlanError("actor does not match the trusted fixture credential binding")
    if step.target_tenant != actor.tenant_id and step.operation not in lane.cross_tenant_operations:
        raise PlanError("cross-tenant action is not a registered fixture exercise")
    resource_id = step.resource_id
    if resource_id is not None and lane.resource_resolver is not None:
        resource_id = lane.resource_resolver(scenario.fixture_seed, resource_id)
    if step.adapter == "browser":
        compile_browser_steps(step, manifest, lane, resource_id=resource_id)
    path = definition.path_template.format(resource_id=resource_id or "")
    action = ActionRequest(
        schema_version="1.1.0",
        action_id=step.node_id,
        adapter=step.adapter,
        operation=step.operation,
        method=definition.method,
        target=ActionTarget(
            url=f"{asset.scheme}://{asset.host}:{asset.port}{path}",
            tenant_id=step.target_tenant,
            resource_id=resource_id,
        ),
        side_effect=definition.side_effect,
        credential_handle=actor.credential_handle,
        idempotency_key=f"{scenario.scenario_id}:{step.node_id}",
        arguments=step.arguments,
        budget=BudgetRequest(
            requests=definition.min_requests,
            writes=int(definition.side_effect == SideEffectClass.WRITE),
            records=definition.min_records,
            tokens=definition.min_tokens,
        ),
    )
    decision = DefaultDenyPolicy(lane.tools).evaluate(manifest, action)
    if not decision.permitted:
        raise PlanError(decision.reason_code)
    return action


def compile_browser_steps(
    step: Step,
    manifest: AuthorizationManifest,
    lane: LaneContract,
    *,
    resource_id: str | None = None,
) -> tuple[BrowserStep, ...]:
    """Resolve a browser step into typed navigate/fill/click/read steps, or refuse it.

    Free-form JavaScript, URLs, and selectors are rejected here, before any policy evaluation
    and long before a browser exists. The expansion comes from the trusted flow registry; the
    planner only selected a registered operation and supplied typed arguments.
    """
    forbidden = FORBIDDEN_BROWSER_KEYS & {key.lower() for key in step.arguments}
    if forbidden:
        raise PlanError(f"free-form browser instruction rejected: {sorted(forbidden)}")
    if manifest.phase2 is None or step.asset_id not in manifest.phase2.browser_assets:
        raise PlanError("browser asset is not signed for browser use")
    flow = lane.flows.get(step.operation)
    if flow is None:
        raise PlanError("browser operation is not a registered flow")
    resolved = resource_id if resource_id is not None else step.resource_id
    try:
        return flow.expand(step.arguments, resolved)
    except ValueError as exc:
        raise PlanError(str(exc)) from exc


def compile_plan(
    scenario: Phase1Scenario,
    manifest: AuthorizationManifest,
    *,
    lane: LaneContract = PHASE1_LANE,
) -> ExecutionPlan:
    scenario.require_runnable()
    actor = lane.actors.get(scenario.actor.actor_id)
    if actor is None or (
        scenario.actor.role,
        scenario.actor.tenant_id,
        scenario.actor.credential_handle,
    ) != (actor.role, actor.tenant_id, actor.credential_handle):
        raise PlanError("actor does not match the trusted fixture credential binding")
    if manifest.schema_version not in lane.manifest_versions or manifest.phase1 is None:
        raise PlanError(f"{lane.name} manifest version required")
    if scenario.schema_version not in lane.scenario_versions:
        raise PlanError(f"{lane.name} scenario version required")
    if lane.requires_phase2:
        if manifest.phase2 is None:
            raise PlanError("Phase 2 grants required")
        if scenario.fixture_seed != manifest.phase2.ownership_seed:
            raise PlanError("signed ownership is bound to a different fixture seed")
    if lane.requires_phase3:
        if manifest.phase3 is None:
            raise PlanError("Phase 3 grants required")
        task = scenario.agent_task
        if task is not None:
            unknown = task.capabilities - INTENT_OPERATIONS
            if unknown:
                raise PlanError(
                    f"declared capability is not an intent operation: {sorted(unknown)}"
                )
            if task.max_steps > manifest.phase3.max_agent_steps:
                raise PlanError("agent task exceeds the signed step limit")
    if len(manifest.assets) != len(lane.expected_assets) or any(
        lane.expected_assets.get(asset.asset_id) != asset.port for asset in manifest.assets
    ):
        raise PlanError(f"manifest must bind the managed {lane.name} fixture listeners")
    if scenario.authorization_digest not in {None, manifest.manifest_digest()}:
        raise PlanError("scenario manifest digest mismatch")
    if scenario.defense_profile not in manifest.phase1.defense_profiles:
        raise PlanError("defense not pre-authorized")
    if scenario.defense_profile not in lane.defenses:
        raise PlanError("defense is not registered for this lane")
    tagged: list[tuple[Literal["clean", "attack"], Step]] = [
        ("clean", s) for s in scenario.clean_steps
    ] + [("attack", s) for s in scenario.attack_steps]
    ids = [s.node_id for _, s in tagged]
    # A chat turn can emit one intent; an agent turn can emit up to the signed per-turn cap. Both
    # are reserved against the signed node budget before anything runs, so a compliant model
    # cannot expand the graph past what was authorized.
    per_agent_turn = manifest.phase3.max_tool_intents_per_turn if manifest.phase3 else 1
    intent_slots = sum(
        1 if s.adapter == "chat" else per_agent_turn if s.adapter == "agent" else 0
        for _, s in tagged
    )
    if len(set(ids)) != len(ids) or len(ids) + intent_slots > manifest.phase1.max_nodes:
        raise PlanError("duplicate nodes or graph exceeds signed limit")
    browser_nodes = sum(s.adapter == "browser" for _, s in tagged)
    if manifest.phase2 is not None and 2 * browser_nodes > manifest.phase2.max_browser_contexts:
        raise PlanError("paired browser legs exceed the signed context limit")
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
            if depths[key] + int(step.adapter in {"chat", "agent"}) > manifest.phase1.max_depth:
                raise PlanError("graph exceeds signed depth")
            nodes.append(
                PlanNode(
                    node_id=key,
                    stage=stage,
                    action=compile_step(step, scenario, manifest, lane=lane),
                    depends_on=step.depends_on,
                    browser_steps=(
                        compile_browser_steps(
                            step,
                            manifest,
                            lane,
                            resource_id=(
                                lane.resource_resolver(scenario.fixture_seed, step.resource_id)
                                if lane.resource_resolver and step.resource_id
                                else step.resource_id
                            ),
                        )
                        if step.adapter == "browser"
                        else None
                    ),
                )
            )
    return ExecutionPlan(
        scenario_id=scenario.scenario_id,
        scenario_digest=scenario.digest(),
        manifest_digest=manifest.manifest_digest(),
        nodes=tuple(nodes),
    )
