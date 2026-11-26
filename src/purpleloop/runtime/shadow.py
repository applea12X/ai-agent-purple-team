"""Shadow execution: decide everything, dispatch nothing, report what would have happened.

Plan §2.2, WP5.1.2-5.1.3, ADR 0014. A shadow run walks a scenario through exactly the steps a
paired run takes -- admission, plan compilation, every control-plane call, both legs, the
utility-under-attack pass, and the attacker's proposals -- and submits each action to the safety
runtime, which admits it, evaluates policy, checks the kill switch, reserves budget, and then
records a ``SHADOW_SUPPRESSED`` event instead of dispatching (``SafetyRuntime.is_shadow``).

Three properties are enforced rather than described:

- **Nothing executes.** The runtime never reaches the adapter in shadow mode, because it does
  not dispatch -- not because an adapter checks a flag. This runner additionally wraps the
  runtime's adapter in :class:`CountingAdapter` and writes the measured count into the ledger;
  :class:`~purpleloop.schemas.phase5.ShadowReport` types ``adapter_calls`` as the literal ``0``,
  so a shadow run that reached an adapter cannot produce a report at all.
- **The report is derived from the ledger.** :func:`build_shadow_report` is a pure function of
  the verified evidence, and :func:`verify_shadow_bundle` recomputes it and refuses a bundle
  whose stored report disagrees -- the report cannot be edited without the ledger.
- **Representativeness is a stated limit.** Nothing executes, so nothing responds: no model
  answers an agent turn and no tool intent it would have produced is reached. Each such slot is
  recorded as an unreachable step (``SHADOW_UNREACHABLE``), counted, and reported -- never
  estimated away. Oracles and detectors are not evaluated; there is no state to score.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import json
from collections import Counter
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal, cast

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import load_pem_public_key

from purpleloop.adapters.base import Adapter, AdapterResult, Authorize
from purpleloop.control.approvals import ApprovalRefused
from purpleloop.control.attacker import (
    AttackerNotAuthorized,
    BoundedAttacker,
    ModelDrivenAttacker,
    Proposal,
    require_attacker_authorized,
)
from purpleloop.control.capabilities import OPERATION_ACTION_CLASSES
from purpleloop.control.lanes import LaneContract
from purpleloop.control.loop_guard import RUNAWAY_LOOP_WOULD_TRIP
from purpleloop.control.manifest import ManifestError
from purpleloop.control.plan_compiler import compile_plan, compile_step
from purpleloop.reporting.bundle import UNINVENTORIED, inventory, write_json
from purpleloop.runtime.fixture import FixtureController
from purpleloop.runtime.ledger import EvidenceLedger
from purpleloop.runtime.runtime import RuntimeResult, SafetyRuntime
from purpleloop.schemas.action import ActionRequest, BudgetRequest, SideEffectClass
from purpleloop.schemas.authorization import SIDE_EFFECT_ACTION_CLASS, AuthorizationManifest
from purpleloop.schemas.common import IDENTIFIER_PATTERN
from purpleloop.schemas.event import SHADOW_EVENT_SCHEMA, EventKind, EvidenceEvent
from purpleloop.schemas.phase1 import Phase1Scenario, Stage, Step
from purpleloop.schemas.phase3 import ProposalRecord
from purpleloop.schemas.phase5 import ActionClass, ShadowReport

SHADOW_REPORT_FILE = "shadow-report.json"
SHADOW_INDEX_FILE = "shadow.json"
REQUESTED_MANIFEST_FILE = "requested-manifest.json"

#: A shadow run's actions, by who asked for them. Plan nodes and control calls are what a paired
#: run would execute; proposals are the attacker's.
Source = Literal["plan", "control", "proposal"]
AttackerFactory = Callable[[], BoundedAttacker | ModelDrivenAttacker]
RuntimeFactory = Callable[[Path], SafetyRuntime]


class ShadowBundleError(ValueError):
    pass


class CountingAdapter:
    """Counts every call into the adapter it wraps. A shadow run must leave every count at zero.

    ``dispatches`` is the number of times an action reached the adapter layer at all (preflight,
    execute, or postcondition). ``cancels`` is counted separately: cancelling an adapter is a
    containment step a kill switch may take, not an execution.
    """

    def __init__(self, inner: Adapter) -> None:
        self.inner = inner
        self.name = f"counting:{getattr(inner, 'name', 'adapter')}"
        self.preflights = 0
        self.executions = 0
        self.postconditions = 0
        self.cancels = 0

    @property
    def dispatches(self) -> int:
        return self.preflights + self.executions + self.postconditions

    async def preflight(self, action: ActionRequest) -> None:
        self.preflights += 1
        await self.inner.preflight(action)

    async def execute(
        self, action: ActionRequest, *, credential: str | None, authorize_target: Authorize
    ) -> AdapterResult:
        self.executions += 1
        return await self.inner.execute(
            action, credential=credential, authorize_target=authorize_target
        )

    async def cancel(self) -> None:
        self.cancels += 1
        await self.inner.cancel()

    async def postcondition(self, action: ActionRequest, result: AdapterResult) -> bool:
        self.postconditions += 1
        return await self.inner.postcondition(action, result)


def _reason_key(reason: str) -> str:
    """A reason as a report key: a reason code stays itself; a sentence becomes ``PLAN_REFUSED``."""
    reason = reason.strip()
    return reason if IDENTIFIER_PATTERN.fullmatch(reason) else "PLAN_REFUSED"


def action_class_of(operation: str, side_effect: str) -> ActionClass:
    """The action class an executed action would have exercised."""
    if operation in OPERATION_ACTION_CLASSES:
        return OPERATION_ACTION_CLASSES[operation]
    return SIDE_EFFECT_ACTION_CLASS[SideEffectClass(side_effect)]


@dataclass
class _ScenarioShadow:
    """One scenario's shadow walk. Mirrors ``PurpleTeamRunner.run`` step for step."""

    runtime: SafetyRuntime
    scenario: Phase1Scenario
    manifest: AuthorizationManifest
    lane: LaneContract
    run_id: str
    attacker_factory: AttackerFactory | None
    controller: FixtureController = field(init=False)
    feedback: list[ProposalRecord] = field(default_factory=list)
    proposal_count: int = 0

    def __post_init__(self) -> None:
        self.controller = FixtureController(
            self.runtime,
            self.manifest,
            self.run_id,
            tools=self.lane.tools,
            control_asset_id=self.lane.control_asset_id,
            credential_handle=self.lane.control_credential_handle,
        )

    # --- evidence ---------------------------------------------------------------------------

    def record(
        self, reason: str, data: dict[str, Any], *, kind: EventKind = EventKind.LIFECYCLE
    ) -> None:
        self.runtime.ledger.append(
            EvidenceEvent(
                schema_version=SHADOW_EVENT_SCHEMA,
                run_id=self.run_id,
                trace_id=f"{self.scenario.scenario_id}-shadow",
                sequence=0,
                timestamp=self.runtime.clock(),
                actor="shadow-runner",
                kind=kind,
                manifest_digest=self.manifest.manifest_digest(),
                policy_digest=getattr(self.runtime.policy, "policy_digest", "0" * 64),
                scenario_id=self.scenario.scenario_id,
                scenario_version=self.scenario.scenario_version,
                stage=self.runtime.stage,
                component_version="shadow-runner-v1",
                reason_code=reason,
                data=self.runtime.redactor.redact(data),
            )
        )

    async def stage(self, stage: Stage) -> None:
        self.runtime.stage = stage
        self.record(stage.upper(), {})
        await self.runtime.kill_switch.ensure_running()

    # --- submission -------------------------------------------------------------------------

    async def submit(self, action: ActionRequest, source: Source) -> RuntimeResult:
        """Submit one action. Anything but suppression is recorded; a stop ends the scenario."""
        result = await self.runtime.run(
            self.manifest,
            action,
            run_id=self.run_id,
            trace_id=f"{self.runtime.stage}-{action.action_id}",
        )
        if result.status == "cancelled":
            raise asyncio.CancelledError
        if result.status == "suppressed":
            return result
        self.record(
            "SHADOW_DENIED",
            {
                "operation": action.operation,
                "source": source,
                "status": result.status,
                "runtime_reason": result.reason_code,
            },
        )
        # A paired run fails closed on any planned, control, or accepted-proposal action that
        # does not complete (``PurpleTeamRunner.action``); the shadow walk ends at the same point,
        # so the report never counts a step the paired run would not have reached.
        raise _Stopped(result.reason_code)

    async def control(self, operation: str, arguments: dict[str, Any] | None = None) -> None:
        await self.submit(self.controller.action_for(operation, arguments), "control")

    async def nodes(self, phase: str, *, variant: str = "") -> None:
        assert self.plan is not None
        start = self.runtime.budgets.used
        for node in self.plan.nodes:
            if node.stage != phase:
                continue
            action = node.action
            if variant:
                action = action.model_copy(
                    update={
                        "action_id": f"{action.action_id}-{variant}",
                        "idempotency_key": f"{action.idempotency_key}:{variant}",
                    }
                )
            self.check_leg_budget(start, action.budget, phase)
            await self.submit(action, "plan")
            if action.adapter in {"chat", "agent"}:
                # Every intent slot the plan reserved for this turn depends on a model response
                # that nothing produced. Recorded per turn, counted in the report.
                slots = (
                    1
                    if action.adapter == "chat"
                    else (
                        self.manifest.phase3.max_tool_intents_per_turn
                        if self.manifest.phase3
                        else 1
                    )
                )
                self.record(
                    "SHADOW_UNREACHABLE",
                    {
                        "node_id": action.action_id,
                        "steps": slots,
                        "reason": "tool intents depend on a model response; nothing responded",
                    },
                )

    def check_leg_budget(
        self, start: BudgetRequest, next_action: BudgetRequest, phase: str
    ) -> None:
        if phase != "attack":
            return
        for name in BudgetRequest.model_fields:
            amount = (
                getattr(self.runtime.budgets.used, name)
                - getattr(start, name)
                + getattr(next_action, name)
            )
            if amount > getattr(self.scenario.attack_budget, name):
                raise _Stopped("SCENARIO_ATTACK_BUDGET_EXCEEDED")

    # --- proposals --------------------------------------------------------------------------

    async def proposals(self, start: BudgetRequest) -> None:
        if self.attacker_factory is None:
            return
        attacker = self.attacker_factory()
        try:
            require_attacker_authorized(attacker, self.manifest)
        except AttackerNotAuthorized as exc:
            self.record(
                "SHADOW_REFUSED",
                {"operation": None, "source": "proposal", "reason": exc.reason_code},
            )
            return
        phase3 = self.manifest.phase3
        cap = phase3.max_attacker_proposals if phase3 is not None else 0
        depth_cap = phase3.max_attacker_depth if phase3 is not None else 0
        if isinstance(attacker, BoundedAttacker):
            await self.run_batch(attacker.proposals(), start, cap, depth_cap)
            return
        while True:
            try:
                round_ = await attacker.next_round(tuple(self.feedback))
            except Exception as exc:  # a failing attacker model ends the search, recorded
                self.record(
                    "SHADOW_PROPOSALS_STOPPED",
                    {"reason": str(getattr(exc, "reason_code", "ATTACKER_MODEL_FAILED"))[:64]},
                )
                return
            if round_ is None:
                return
            tokens = round_.input_tokens + round_.output_tokens
            self.record(
                "ATTACKER_MODEL_CALLED",
                {
                    "pin_id": attacker.pin.pin_id,
                    "depth": round_.depth,
                    "prompt_digest": round_.prompt_digest,
                    "response_digest": round_.response_digest,
                    "input_tokens": round_.input_tokens,
                    "output_tokens": round_.output_tokens,
                },
                kind=EventKind.MODEL,
            )
            try:
                await self.runtime.budgets.charge(
                    BudgetRequest(requests=0, records=0, tokens=tokens)
                )
            except Exception as exc:
                self.record(
                    "SHADOW_PROPOSALS_STOPPED",
                    {"reason": str(getattr(exc, "reason_code", "BUDGET_EXCEEDED"))},
                )
                return
            for operation, reason in round_.invalid:
                self.reject(operation, reason, round_.depth)
            if not round_.proposals:
                return
            if not await self.run_batch(round_.proposals, start, cap, depth_cap):
                return

    def reject(self, operation: str, reason: str, depth: int) -> None:
        record = ProposalRecord(
            proposal_index=self.proposal_count,
            depth=depth,
            operation=operation[:64],
            accepted=False,
            reason_code=_reason_key(reason),
        )
        self.proposal_count += 1
        self.feedback.append(record)
        self.record(record.reason_code, record.model_dump(mode="json"), kind=EventKind.PROPOSAL)

    async def run_batch(
        self, batch: Sequence[Proposal], start: BudgetRequest, cap: int, depth_cap: int
    ) -> bool:
        """Compile, decide, and suppress each proposal. False once a cap or budget stops it.

        The caps are read from the signed manifest here, independently of the attacker: an
        attacker object that ignores its own caps is still stopped at the signed ones.
        """
        for proposal in batch:
            if self.proposal_count >= cap or proposal.depth > depth_cap:
                self.record("SHADOW_PROPOSALS_STOPPED", {"reason": "PROPOSAL_CAP_REACHED"})
                return False
            step = Step(
                node_id=f"proposal-{self.proposal_count}",
                adapter=cast(
                    'Literal["http", "tool", "chat", "browser", "agent"]',
                    BoundedAttacker.adapter_for(proposal.operation),
                ),
                operation=proposal.operation,
                asset_id=self.lane.data_asset_id,
                target_tenant=proposal.target_tenant,
                resource_id=proposal.resource_id,
                arguments=proposal.arguments,
            )
            try:
                compiled = compile_step(step, self.scenario, self.manifest, lane=self.lane)
            except ValueError as exc:
                reason = str(getattr(exc, "reason_code", exc))
                self.reject(proposal.operation, reason, proposal.depth)
                # The loop detector sees the refusal too; in shadow it only ever reports.
                self.runtime.refused_step(
                    self.manifest,
                    step,
                    _reason_key(reason),
                    run_id=self.run_id,
                    trace_id=f"{self.runtime.stage}-{step.node_id}",
                )
                continue
            record = ProposalRecord(
                proposal_index=self.proposal_count,
                depth=proposal.depth,
                operation=proposal.operation,
                accepted=True,
                reason_code="PROPOSAL_ACCEPTED",
                node_id=step.node_id,
            )
            self.proposal_count += 1
            try:
                self.check_leg_budget(start, compiled.budget, "attack")
            except _Stopped:
                self.record("SHADOW_PROPOSALS_STOPPED", {"reason": "PROPOSAL_BUDGET_EXHAUSTED"})
                return False
            self.record(record.reason_code, record.model_dump(mode="json"), kind=EventKind.PROPOSAL)
            await self.submit(compiled, "proposal")
            self.feedback.append(record)
        return True

    # --- the walk ---------------------------------------------------------------------------

    plan: Any = None

    async def leg(self, name: str) -> None:
        await self.control("snapshot")
        await self.stage(Stage.CLEAN if name == "baseline" else Stage.REPLAY_CLEAN)
        await self.nodes("clean")
        await self.control("snapshot")
        await self.control("telemetry")
        await self.stage(Stage.ATTACK if name == "baseline" else Stage.REPLAY)
        attack_start = self.runtime.budgets.used
        await self.nodes("attack")
        await self.control("snapshot")
        await self.control("telemetry")
        await self.stage(Stage.SCORE)
        self.record("SHADOW_NOT_SCORED", {"leg": name, "reason": "nothing executed to score"})
        if self.lane.requires_phase3 and self.scenario.utility_oracle is not None:
            await self.nodes("clean", variant="under-attack")
            await self.control("snapshot")
        if self.attacker_factory is not None:
            self.record(
                "ADVISORY_PROBES_AFTER_BINDING",
                {"note": "actions after this event are advisory probes excluded from scoring"},
            )
            await self.proposals(attack_start)

    async def run(self) -> str:
        self.runtime.scenario_id = self.scenario.scenario_id
        self.runtime.scenario_version = self.scenario.scenario_version
        self.record(
            "SHADOW_SCENARIO",
            {"scenario_digest": self.scenario.digest(), "lane": self.lane.name},
        )
        reason = "SHADOW_COMPLETE"
        try:
            await self.stage(Stage.ADMISSION)
            self.runtime.verifier.verify(self.manifest, now=self.runtime.clock())
            self.runtime.admit(
                self.manifest, run_id=self.run_id, trace_id=f"{self.scenario.scenario_id}-admission"
            )
            self.plan = compile_plan(self.scenario, self.manifest, lane=self.lane)
            await self.stage(Stage.PROVISION)
            await self.control("provision")
            await self.stage(Stage.SEED)
            await self.control("seed", self.lane.seed_arguments(self.scenario))
            await self.leg("baseline")
            await self.stage(Stage.DEFENSE)
            await self.control("defense", {"profile": self.scenario.defense_profile})
            await self.stage(Stage.RESET)
            await self.control("reset")
            await self.leg("replay")
        except _Stopped as stop:
            reason = stop.reason_code
            self.record("SHADOW_STOPPED", {"reason": reason})
        except (ApprovalRefused, ManifestError) as exc:
            reason = exc.reason_code
            self.record(
                "SHADOW_REFUSED", {"operation": None, "source": "admission", "reason": reason}
            )
        except ValueError as exc:
            reason = _reason_key(str(getattr(exc, "reason_code", exc)))
            self.record("SHADOW_REFUSED", {"operation": None, "source": "plan", "reason": reason})
        finally:
            # Teardown of nothing: its decision is recorded either way, and a refused teardown
            # (a stopped kernel, an exhausted budget) must not hide the adapter count below.
            with contextlib.suppress(_Stopped, ValueError, ManifestError):
                self.runtime.stage = Stage.TEARDOWN
                await self.control("teardown")
            counter = self.runtime.adapter
            dispatches = counter.dispatches if isinstance(counter, CountingAdapter) else -1
            self.runtime.stage = Stage.TERMINATED
            self.record("SHADOW_ADAPTER_CALLS", {"dispatches": dispatches})
            self.record("SHADOW_TERMINATED", {"reason": reason}, kind=EventKind.TERMINATION)
        return reason


def _make_directory(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    return path


class _Stopped(Exception):
    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


class ShadowRunner:
    """Runs scenarios in shadow, one fresh runtime and ledger per scenario, into one bundle.

    ``runtime_factory`` builds the runtime a paired run of the same lane would use -- the real
    adapters included -- given the scenario's bundle directory. The runner forces it into shadow
    mode and wraps its adapter in a :class:`CountingAdapter` before submitting anything.
    """

    def __init__(
        self,
        runtime_factory: RuntimeFactory,
        *,
        lane: LaneContract,
        attacker_factory: AttackerFactory | None = None,
    ) -> None:
        self.runtime_factory = runtime_factory
        self.lane = lane
        self.attacker_factory = attacker_factory
        self.counters: dict[str, CountingAdapter] = {}

    async def run(
        self,
        scenarios: Sequence[Phase1Scenario],
        manifest: AuthorizationManifest,
        *,
        run_id: str,
        output_dir: Path,
        public_key_pem: bytes,
        requested: AuthorizationManifest | None = None,
        now: datetime | None = None,
    ) -> ShadowReport:
        if not scenarios:
            raise ValueError("a shadow run needs at least one scenario")
        ids = [scenario.scenario_id for scenario in scenarios]
        if len(ids) != len(set(ids)):
            raise ValueError("shadow scenarios must be distinct")
        for scenario in scenarios:
            directory = _make_directory(output_dir / scenario.scenario_id)
            runtime = self.runtime_factory(directory)
            # Forced, and never unset: the shadow runner has no path that dispatches.
            runtime.shadow = True
            counter = CountingAdapter(runtime.adapter)
            runtime.adapter = counter
            self.counters[scenario.scenario_id] = counter
            await _ScenarioShadow(
                runtime, scenario, manifest, self.lane, run_id, self.attacker_factory
            ).run()
            write_json(
                directory / "scenario.json", scenario.model_dump(mode="json", exclude_none=True)
            )
            ledger = runtime.ledger
            if ledger.path.resolve() != (directory / "evidence.jsonl").resolve():
                raise ShadowBundleError("the runtime ledger must live in the scenario directory")
        write_json(
            output_dir / "manifest.json", manifest.model_dump(mode="json", exclude_none=True)
        )
        (output_dir / "authorization-public.pem").write_bytes(public_key_pem)
        if requested is not None:
            write_json(
                output_dir / REQUESTED_MANIFEST_FILE,
                requested.model_dump(mode="json", exclude_none=True),
            )
        write_json(
            output_dir / SHADOW_INDEX_FILE,
            {"schema_version": "1.0.0", "run_id": run_id, "scenarios": ids},
        )
        report = build_shadow_report(
            {sid: EvidenceLedger(output_dir / sid / "evidence.jsonl").verify() for sid in ids},
            run_id=run_id,
            manifest=manifest,
            created_at=now or datetime.now(UTC),
        )
        write_json(
            output_dir / SHADOW_REPORT_FILE, report.model_dump(mode="json", exclude_none=True)
        )
        inventory(output_dir, complete=True)
        return report


def build_shadow_report(
    ledgers: dict[str, list[EvidenceEvent]],
    *,
    run_id: str,
    manifest: AuthorizationManifest,
    created_at: datetime,
) -> ShadowReport:
    """The shadow report, derived from verified evidence only. Pure.

    Raises (``ValidationError``) when any scenario recorded a non-zero adapter dispatch count:
    ``ShadowReport.adapter_calls`` admits only zero.
    """
    operations: Counter[str] = Counter()
    denials: Counter[str] = Counter()
    classes: set[ActionClass] = set()
    budget = dict.fromkeys(BudgetRequest.model_fields, 0)
    scenario_digests: list[str] = []
    proposals_total = rejected = suppressed = unreachable = dispatches = loops = 0
    for events in ledgers.values():
        for event in events:
            data = event.data
            reason = event.reason_code or ""
            if event.kind == EventKind.POLICY and reason == RUNAWAY_LOOP_WOULD_TRIP:
                loops += 1
                continue
            if event.kind == EventKind.SHADOW_SUPPRESSED:
                suppressed += 1
                operations[str(data["operation"])] += 1
                classes.add(action_class_of(str(data["operation"]), str(data["side_effect"])))
                for name, amount in dict(data.get("budget", {})).items():
                    budget[name] += int(amount)
                continue
            if event.actor != "shadow-runner":
                continue
            if event.kind == EventKind.PROPOSAL:
                proposals_total += 1
                if not data.get("accepted"):
                    rejected += 1
                    denials[_reason_key(reason)] += 1
                    operation = str(data.get("operation", ""))
                    if operation != "invalid" and IDENTIFIER_PATTERN.fullmatch(operation):
                        operations[operation] += 1
            elif reason == "SHADOW_SCENARIO":
                scenario_digests.append(str(data["scenario_digest"]))
            elif reason == "SHADOW_DENIED":
                operations[str(data["operation"])] += 1
                denials[_reason_key(str(data["runtime_reason"]))] += 1
                if data.get("source") == "proposal":
                    rejected += 1
            elif reason == "SHADOW_REFUSED":
                denials[_reason_key(str(data["reason"]))] += 1
            elif reason == "SHADOW_UNREACHABLE":
                unreachable += int(data["steps"])
            elif reason == "SHADOW_ADAPTER_CALLS":
                count = int(data["dispatches"])
                # -1 means the count was not measured; that is not zero, and fails closed.
                dispatches += count if count >= 0 else 1
    total_with_runtime = proposals_total
    return ShadowReport.model_validate(
        {
            "run_id": run_id,
            "engagement_id": manifest.engagement_id,
            "manifest_digest": manifest.manifest_digest(),
            "scenario_digests": tuple(scenario_digests),
            "action_classes_reached": frozenset(classes),
            "operations_proposed": dict(sorted(operations.items())),
            "denials_by_reason": dict(sorted(denials.items())),
            "would_be_budget": BudgetRequest(**budget),
            "proposals_total": total_with_runtime,
            "proposals_rejected": min(rejected, total_with_runtime),
            "proposal_rejection_rate": (
                min(rejected, total_with_runtime) / total_with_runtime
                if total_with_runtime
                else 0.0
            ),
            "suppressed_executions": suppressed,
            "unreachable_steps": unreachable,
            "adapter_calls": dispatches,
            "created_at": created_at,
            # Absent rather than zero, so a report with no would-be loop keeps its digest.
            "would_be_loops": loops or None,
        }
    )


def _read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def verify_shadow_bundle(directory: Path) -> ShadowReport:
    """Verify a shadow bundle end to end and return its report. Raises on any disagreement.

    Checks: a complete inventory that matches the directory byte for byte; the manifest
    signature against the key beside it; every scenario ledger's hash chain and its binding to
    that manifest; each stored scenario against the digest its ledger recorded; and the stored
    report against the report recomputed from the ledgers.
    """
    try:
        raw = _read_json(directory / "inventory.json")
    except (OSError, ValueError) as exc:
        raise ShadowBundleError("not a shadow bundle: inventory.json is unreadable") from exc
    if raw.get("schema_version") != "1.1.0" or not raw.get("complete"):
        raise ShadowBundleError("shadow bundle inventory is missing or incomplete")
    artifacts: dict[str, str] = raw.get("artifacts", {})
    actual = {
        p.relative_to(directory).as_posix()
        for p in directory.rglob("*")
        if p.is_file() and p.relative_to(directory).as_posix() not in UNINVENTORIED
    }
    if actual != set(artifacts):
        raise ShadowBundleError("artifact inventory differs from directory")
    for name, digest in artifacts.items():
        path = directory / name
        if ".." in Path(name).parts or path.is_symlink():
            raise ShadowBundleError("unsafe artifact path")
        if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            raise ShadowBundleError(f"artifact digest mismatch: {name}")
    for required in (
        SHADOW_REPORT_FILE,
        SHADOW_INDEX_FILE,
        "manifest.json",
        "authorization-public.pem",
    ):
        if required not in artifacts:
            raise ShadowBundleError(f"required artifact missing: {required}")
    manifest = AuthorizationManifest.model_validate(_read_json(directory / "manifest.json"))
    key = load_pem_public_key((directory / "authorization-public.pem").read_bytes())
    if not isinstance(key, Ed25519PublicKey):
        raise ShadowBundleError("invalid authorization key type")
    import base64

    from cryptography.exceptions import InvalidSignature

    try:
        key.verify(base64.b64decode(manifest.signature, validate=True), manifest.signed_bytes())
    except (InvalidSignature, ValueError) as exc:
        raise ShadowBundleError("shadow manifest signature is invalid") from exc
    index = _read_json(directory / SHADOW_INDEX_FILE)
    ids = index.get("scenarios", [])
    if not ids or len(ids) != len(set(ids)) or any(Path(i).name != i for i in ids):
        raise ShadowBundleError("invalid shadow scenario list")
    digest = manifest.manifest_digest()
    ledgers: dict[str, list[EvidenceEvent]] = {}
    for sid in ids:
        events = EvidenceLedger(directory / sid / "evidence.jsonl").verify()
        if not events or any(event.manifest_digest != digest for event in events):
            raise ShadowBundleError(f"{sid}: events are not bound to the shadow manifest")
        scenario = Phase1Scenario.model_validate(_read_json(directory / sid / "scenario.json"))
        recorded = [
            e.data.get("scenario_digest") for e in events if e.reason_code == "SHADOW_SCENARIO"
        ]
        if recorded != [scenario.digest()]:
            raise ShadowBundleError(f"{sid}: scenario digest mismatch")
        ledgers[sid] = events
    stored = ShadowReport.model_validate(_read_json(directory / SHADOW_REPORT_FILE))
    recomputed = build_shadow_report(
        ledgers, run_id=stored.run_id, manifest=manifest, created_at=stored.created_at
    )
    if recomputed.report_digest() != stored.report_digest():
        raise ShadowBundleError("the stored shadow report disagrees with its ledgers")
    if stored.run_id != index.get("run_id"):
        raise ShadowBundleError("shadow run id mismatch")
    return stored


def load_requested_manifest(directory: Path) -> AuthorizationManifest:
    """The execute manifest a shadow bundle was produced for (written by ``shadow-run``)."""
    path = directory / REQUESTED_MANIFEST_FILE
    if not path.exists():
        raise ShadowBundleError("the shadow bundle names no requested manifest")
    return AuthorizationManifest.model_validate(_read_json(path))
