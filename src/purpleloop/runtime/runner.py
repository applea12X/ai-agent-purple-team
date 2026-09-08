from __future__ import annotations

import asyncio
import time
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any, Protocol

from purpleloop.control.lanes import PHASE1_LANE, LaneContract
from purpleloop.control.phase1_tools import ChatArgs, ToolIntent
from purpleloop.control.plan_compiler import compile_plan, compile_step
from purpleloop.runtime.fixture import FixtureController
from purpleloop.runtime.replay import replay_fingerprint
from purpleloop.runtime.runtime import SafetyRuntime
from purpleloop.schemas.action import ActionRequest, BudgetRequest
from purpleloop.schemas.authorization import AuthorizationManifest
from purpleloop.schemas.common import digest_data
from purpleloop.schemas.event import EventKind, EvidenceEvent
from purpleloop.schemas.phase1 import (
    DefenseSelection,
    ExecutionPlan,
    Finding,
    LegResult,
    Phase1Scenario,
    RunSummary,
    Stage,
    Step,
)
from purpleloop.schemas.phase2 import BrowserArtifact, ResourceUsage
from purpleloop.scoring.phase1 import detect, evaluate
from purpleloop.scoring.phase2 import estimate_resources, evidence_completeness, resource_report


class BrowserProbe(Protocol):
    """Read-only view of what the browser adapter did, for the run summary."""

    @property
    def driver_name(self) -> str: ...

    @property
    def contexts_opened(self) -> int: ...

    @property
    def artifacts(self) -> tuple[BrowserArtifact, ...]: ...


class PurpleTeamRunner:
    def __init__(
        self,
        runtime: SafetyRuntime,
        *,
        close: Callable[[], Awaitable[None]],
        stage_hook: Callable[[Stage], Awaitable[None]] | None = None,
        lane: LaneContract = PHASE1_LANE,
        browser: BrowserProbe | None = None,
    ) -> None:
        self.runtime = runtime
        self.close = close
        self.stage_hook = stage_hook
        self.lane = lane
        self.browser = browser
        self.started = time.monotonic()
        self.snapshots: dict[str, dict[str, Any]] = {}
        self.plan: ExecutionPlan | None = None
        self.estimate: ResourceUsage | None = None
        self.scenario: Phase1Scenario
        self.manifest: AuthorizationManifest
        self.run_id: str
        self.controller: FixtureController

    def record(self, kind: EventKind, reason: str, data: dict[str, Any]) -> str:
        event = self.runtime.ledger.append(
            EvidenceEvent(
                schema_version="1.1.0",
                run_id=self.run_id,
                trace_id=f"{self.scenario.scenario_id}-lifecycle",
                sequence=0,
                timestamp=self.runtime.clock(),
                actor="purple-team-runner",
                kind=kind,
                manifest_digest=self.manifest.manifest_digest(),
                policy_digest=getattr(self.runtime.policy, "policy_digest", "0" * 64),
                scenario_id=self.scenario.scenario_id,
                scenario_version=self.scenario.scenario_version,
                stage=self.runtime.stage,
                component_version="runner-v1",
                reason_code=reason,
                data=self.runtime.redactor.redact(data),
            )
        )
        return event.event_hash or ""

    async def stage(self, stage: Stage) -> None:
        self.runtime.stage = stage
        self.record(EventKind.LIFECYCLE, stage.upper(), {})
        if self.stage_hook:
            await self.stage_hook(stage)
        await self.runtime.kill_switch.ensure_running()

    async def action(self, action: ActionRequest) -> tuple[dict[str, Any], tuple[str, ...]]:
        result = await self.runtime.run(
            self.manifest,
            action,
            run_id=self.run_id,
            trace_id=f"{self.runtime.stage}-{action.action_id}",
        )
        if result.status == "cancelled":
            raise asyncio.CancelledError
        if result.status != "completed" or result.result is None:
            raise RuntimeError(result.reason_code)
        return result.result.data, result.event_hashes

    async def execute_steps(self, phase: str) -> tuple[list[dict[str, Any]], tuple[str, ...], bool]:
        assert self.plan is not None
        responses: list[dict[str, Any]] = []
        evidence: list[str] = []
        susceptible = False
        start_budget = self.runtime.budgets.used
        dynamic_count = 0
        for node in self.plan.nodes:
            if node.stage != phase:
                continue
            action = node.action
            if action.adapter == "chat":
                args = ChatArgs.model_validate(action.arguments)
                if args.retrieved == "$previous.body":
                    body = responses[-1].get("value", {}).get("body") if responses else None
                    if not isinstance(body, str):
                        raise ValueError("retrieved content is missing")
                    action = ActionRequest.model_validate(
                        {
                            **action.model_dump(),
                            "arguments": {**args.model_dump(), "retrieved": body},
                        }
                    )
            self.check_leg_budget(start_budget, action.budget, phase)
            response, ids = await self.action(action)
            responses.append(response)
            evidence.extend(ids)
            if action.adapter == "chat":
                intents = response.get("tool_intents", [])
                susceptible = bool(intents)
                for raw in intents:
                    intent = ToolIntent.model_validate(raw)
                    dynamic_count += 1
                    assert self.manifest.phase1 is not None
                    if (
                        len(self.plan.nodes) + dynamic_count > self.manifest.phase1.max_nodes
                        or self.manifest.phase1.max_depth < 2
                    ):
                        raise ValueError("dynamic tool intent exceeds graph limits")
                    step = Step(
                        node_id=f"{node.node_id}-intent-{dynamic_count}",
                        adapter="tool",
                        operation=intent.operation,
                        asset_id=self.lane.data_asset_id,
                        target_tenant=self.scenario.actor.tenant_id,
                        arguments=intent.arguments.model_dump(mode="json"),
                    )
                    compiled = compile_step(step, self.scenario, self.manifest, lane=self.lane)
                    self.record(
                        EventKind.LIFECYCLE,
                        "TOOL_INTENT_COMPILED",
                        {"action": compiled.model_dump(mode="json")},
                    )
                    self.check_leg_budget(start_budget, compiled.budget, phase)
                    tool_response, tool_ids = await self.action(compiled)
                    responses.append(tool_response)
                    evidence.extend(tool_ids)
        return responses, tuple(evidence), susceptible

    def check_leg_budget(
        self, start: BudgetRequest, next_action: BudgetRequest, phase: str
    ) -> None:
        if phase != "attack":
            return
        for field in BudgetRequest.model_fields:
            amount = (
                getattr(self.runtime.budgets.used, field)
                - getattr(start, field)
                + getattr(next_action, field)
            )
            if amount > getattr(self.scenario.attack_budget, field):
                raise ValueError("scenario attack budget exceeded")

    async def leg(self, name: str, seed_hash: str) -> LegResult:
        before = await self.controller.call("snapshot")
        if before["state_hash"] != seed_hash:
            raise ValueError("fixture seed hash mismatch")
        self.snapshots[f"{name}-before"] = before
        await self.stage(Stage.CLEAN if name == "baseline" else Stage.REPLAY_CLEAN)
        clean, clean_ids, _ = await self.execute_steps("clean")
        clean_state = await self.controller.call("snapshot")
        assert (
            self.scenario.utility_oracle is not None and self.scenario.security_oracle is not None
        )
        utility = evaluate(
            self.scenario.utility_oracle,
            before=before["state"],
            state=clean_state["state"],
            responses=clean,
            telemetry=[],
            evidence_ids=clean_ids,
        )
        clean_telemetry = await self.controller.call("telemetry")
        first_attack_tick = len(clean_telemetry["events"]) + 1
        await self.stage(Stage.ATTACK if name == "baseline" else Stage.REPLAY)
        responses, action_ids, susceptible = await self.execute_steps("attack")
        after = await self.controller.call("snapshot")
        snapshot_ids = self.controller.last_evidence_ids
        self.snapshots[f"{name}-after"] = after
        telemetry = await self.controller.call("telemetry")
        telemetry_id = self.controller.last_evidence_ids[-1]
        events = telemetry["events"][first_attack_tick - 1 :]
        await self.stage(Stage.SCORE)
        security = evaluate(
            self.scenario.security_oracle,
            before=clean_state["state"],
            state=after["state"],
            responses=responses,
            telemetry=events,
            evidence_ids=(*action_ids, *snapshot_ids),
        )
        self.record(
            EventKind.ORACLE,
            f"{name.upper()}_SCORED",
            {
                "utility": utility.model_dump(mode="json"),
                "security": security.model_dump(mode="json"),
            },
        )
        await self.stage(Stage.DETECT)
        detectors = detect(
            events, self.scenario.expected_telemetry, telemetry_id, first_attack_tick
        )
        self.record(
            EventKind.DETECTOR,
            "DETECTORS_SCORED",
            {"results": [d.model_dump(mode="json") for d in detectors]},
        )
        return LegResult(
            seed_hash=seed_hash,
            utility=utility,
            security=security,
            susceptible=susceptible or security.verdict == "true",
            unauthorized_side_effects=sum(bool(e["unauthorized"] and e["write"]) for e in events),
            detectors=detectors,
        )

    async def run(
        self,
        scenario: Phase1Scenario,
        manifest: AuthorizationManifest,
        *,
        run_id: str,
        output_dir: Path,
    ) -> RunSummary:
        self.scenario, self.manifest, self.run_id = scenario, manifest, run_id
        self.runtime.scenario_id, self.runtime.scenario_version = (
            scenario.scenario_id,
            scenario.scenario_version,
        )
        self.controller = FixtureController(
            self.runtime,
            manifest,
            run_id,
            tools=self.lane.tools,
            control_asset_id=self.lane.control_asset_id,
            credential_handle=self.lane.control_credential_handle,
        )
        summary = RunSummary(
            run_id=run_id,
            scenario_id=scenario.scenario_id,
            status="error",
            reason="RUN_NOT_COMPLETED",
            manifest_digest=manifest.manifest_digest(),
            scenario_digest=scenario.digest(),
        )
        cancelled = False
        try:
            await self.stage(Stage.ADMISSION)
            self.runtime.verifier.verify(manifest, now=self.runtime.clock())
            self.plan = compile_plan(scenario, manifest, lane=self.lane)
            summary = summary.model_copy(update={"plan_digest": self.plan.digest()})
            if self.lane is not PHASE1_LANE:
                self.estimate = estimate_resources(self.plan, self.lane)
                self.record(
                    EventKind.LIFECYCLE,
                    "RESOURCE_ESTIMATE",
                    self.estimate.model_dump(mode="json"),
                )
            await self.stage(Stage.PROVISION)
            await self.controller.call("provision")
            await self.stage(Stage.SEED)
            seeded = await self.controller.call("seed", self.lane.seed_arguments(scenario))
            baseline = await self.leg("baseline", seeded["state_hash"])
            summary = summary.model_copy(update={"baseline": baseline})
            await self.stage(Stage.DEFENSE)
            applicable, config = self.lane.defenses[scenario.defense_profile]
            if (
                scenario.scenario_id not in applicable
                or manifest.phase1 is None
                or scenario.defense_profile not in manifest.phase1.defense_profiles
            ):
                raise ValueError("defense is not applicable or pre-authorized")
            applied = await self.controller.call("defense", {"profile": scenario.defense_profile})
            if applied["configuration"] != config:
                raise ValueError("defense configuration verification failed")
            selection = DefenseSelection(
                profile=scenario.defense_profile,
                scenario_id=scenario.scenario_id,
                configuration=config,
                verified=True,
            )
            self.record(EventKind.DEFENSE, "DEFENSE_VERIFIED", selection.model_dump(mode="json"))
            summary = summary.model_copy(update={"defense": selection})
            await self.stage(Stage.RESET)
            reset = await self.controller.call("reset")
            if reset["state_hash"] != seeded["state_hash"] or reset["configuration"] != config:
                raise ValueError("reset state or defense drift")
            replay = await self.leg("replay", seeded["state_hash"])
            effective = baseline.security.verdict == "true" and replay.security.verdict == "false"
            regression = baseline.utility.verdict == "true" and replay.utility.verdict != "true"
            findings: tuple[Finding, ...] = ()
            if baseline.security.verdict == "true":
                assert scenario.security_oracle is not None
                findings = (
                    Finding(
                        finding_id=f"{scenario.scenario_id}-seeded",
                        scenario_id=scenario.scenario_id,
                        asset_id=self.lane.data_asset_id,
                        attacker_goal=scenario.attacker_objective,
                        observed_impact=(
                            f"{scenario.security_oracle.operator}: {baseline.security.observed}"
                        ),
                        evidence_ids=baseline.security.evidence_ids,
                        oracle_version=baseline.security.oracle_version,
                        manifest_digest=manifest.manifest_digest(),
                        scenario_digest=scenario.digest(),
                        seed_hash=seeded["state_hash"],
                        reproducible=False,
                        severity_rationale=(
                            "Synthetic cross-tenant disclosure or unauthorized protected operation."
                        ),
                        taxonomy_mappings=scenario.taxonomy_mappings,
                        status="confirmed",
                        mitigation=scenario.defense_profile,
                    ),
                )
            inconclusive = any(
                r.verdict == "inconclusive"
                for r in (baseline.security, baseline.utility, replay.security, replay.utility)
            )
            status = (
                "inconclusive"
                if inconclusive or baseline.security.verdict != "true"
                else (
                    "passed"
                    if effective and not regression and baseline.utility.verdict == "true"
                    else "regression"
                )
            )
            summary = summary.model_copy(
                update={
                    "status": status,
                    "reason": "PAIRED_EVALUATION",
                    "replay": replay,
                    "mitigation_effective": effective,
                    "utility_regression": regression,
                    "findings": findings,
                }
            )
        except asyncio.CancelledError:
            cancelled = True
            summary = summary.model_copy(update={"status": "error", "reason": "CANCELLED"})
        except Exception as exc:
            summary = summary.model_copy(
                update={
                    "status": "error",
                    "reason": str(getattr(exc, "reason_code", type(exc).__name__)),
                }
            )
        finally:
            cleanup = asyncio.create_task(self.cleanup(summary))
            try:
                summary = await asyncio.shield(cleanup)
            except asyncio.CancelledError:
                cancelled = True
                summary = await cleanup
            from purpleloop.reporting.bundle import write_run

            write_run(
                output_dir,
                summary,
                scenario,
                manifest,
                self.plan,
                self.runtime.ledger,
                self.snapshots,
                self.runtime.redactor,
                self.runtime.verifier.public_key_bytes(manifest.key_id),
            )
        if cancelled:
            raise asyncio.CancelledError
        return summary

    async def cleanup(self, summary: RunSummary) -> RunSummary:
        integrity = False
        tokens_used = 0
        executed_actions = 0
        teardown = False
        completeness = None
        try:
            async with asyncio.timeout(5):
                try:
                    await self.stage(Stage.TEARDOWN)
                    await self.controller.call("teardown")
                finally:
                    # Host-owned containment disposal remains possible after kernel termination.
                    await self.close()
                    teardown = True
        except (Exception, asyncio.CancelledError) as exc:
            summary = summary.model_copy(
                update={
                    "status": "error",
                    "reason": f"{summary.reason}; cleanup: {type(exc).__name__}",
                }
            )
        try:
            self.runtime.stage = Stage.TERMINATED
            self.record(
                EventKind.TERMINATION,
                summary.reason,
                {"status": summary.status, "teardown_complete": teardown},
            )
            events = self.runtime.ledger.verify()
            event_hash = replay_fingerprint(events)
            for event in events:
                if event.kind == EventKind.RESULT and event.reason_code == "COMPLETED":
                    executed_actions += 1
                    output = event.data.get("data", {})
                    tokens_used += int(output.get("input_tokens", 0)) + int(
                        output.get("output_tokens", 0)
                    )
            if self.lane is not PHASE1_LANE:
                completeness = evidence_completeness(events)
        except Exception:
            integrity, event_hash = True, None
        elapsed = time.monotonic() - self.started
        phase2_fields: dict[str, Any] = {}
        if self.lane is not PHASE1_LANE:
            actual = ResourceUsage(
                requests=self.runtime.budgets.used.requests,
                records=self.runtime.budgets.used.records,
                browser_contexts=self.browser.contexts_opened if self.browser else 0,
                wall_time_seconds=round(elapsed, 6),
            )
            phase2_fields = {
                "lane": self.lane.name,
                "surface": self.scenario.effective_surface,
                "resources": (
                    resource_report(self.estimate, actual) if self.estimate is not None else None
                ),
                "evidence_completeness": completeness,
                "browser_driver": self.browser.driver_name if self.browser else None,
                "browser_artifacts": (
                    tuple(artifact.path for artifact in self.browser.artifacts)
                    if self.browser
                    else None
                ),
            }
        return summary.model_copy(
            update={
                "teardown_complete": teardown,
                "elapsed_seconds": elapsed,
                "tokens_used": tokens_used,
                "executed_actions": executed_actions,
                "budget_used": self.runtime.budgets.used,
                "event_replay_hash": event_hash,
                "oracle_hash": digest_data(
                    {
                        "baseline": summary.baseline.model_dump(
                            mode="json",
                            exclude={
                                "security": {"evidence_ids"},
                                "utility": {"evidence_ids"},
                                "detectors": {"__all__": {"evidence_ids"}},
                            },
                        )
                        if summary.baseline
                        else None,
                        "replay": summary.replay.model_dump(
                            mode="json",
                            exclude={
                                "security": {"evidence_ids"},
                                "utility": {"evidence_ids"},
                                "detectors": {"__all__": {"evidence_ids"}},
                            },
                        )
                        if summary.replay
                        else None,
                    }
                ),
                "evidence_integrity_incident": integrity,
                "status": "error" if integrity or not teardown else summary.status,
                **phase2_fields,
            }
        )
