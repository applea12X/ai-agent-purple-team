from __future__ import annotations

import asyncio
from collections.abc import Callable
from datetime import UTC, datetime
from typing import cast

from pydantic import computed_field

from purpleloop.adapters.base import Adapter, AdapterResult, SubresourceDenied
from purpleloop.control.approvals import AdmissionDecision, ApprovalAdmission, ApprovalRefused
from purpleloop.control.budgets import BudgetError, BudgetLedger, Reservation
from purpleloop.control.credentials import CredentialBroker
from purpleloop.control.kill_switch import KernelState, KernelStopped, KillSwitch
from purpleloop.control.loop_guard import (
    CONTROL_ADAPTER,
    RUNAWAY_LOOP_DETECTED,
    RUNAWAY_LOOP_WOULD_TRIP,
    LoopGuard,
    LoopTrip,
    action_fingerprint,
    outcome_digest,
    rejected_fingerprint,
    step_fingerprint,
    stricter_grant,
)
from purpleloop.control.manifest import ManifestError, ManifestVerifier
from purpleloop.control.policy import PolicyEngine
from purpleloop.control.redaction import Redactor
from purpleloop.control.targets import (
    TargetError,
    canonicalize_url,
    match_scope,
    validate_observation,
)
from purpleloop.runtime.ledger import EvidenceLedger
from purpleloop.schemas.action import ActionRequest, ActionTarget, BudgetRequest, TargetObservation
from purpleloop.schemas.authorization import AuthorizationManifest
from purpleloop.schemas.common import StrictModel, digest_data
from purpleloop.schemas.event import SHADOW_EVENT_SCHEMA, EventKind, EvidenceEvent
from purpleloop.schemas.phase1 import Step
from purpleloop.schemas.phase5 import LoopGuardGrant


class BoundaryDenied(RuntimeError):
    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


#: Upper bound on a failure detail. An exception message can quote a whole response body; the
#: ledger records why an action failed, not what the target said at length.
MAX_FAILURE_DETAIL = 200


def failure_detail(exc: BaseException) -> str:
    """One bounded line naming an execution failure. Callers redact it before it is recorded."""
    return " ".join(f"{type(exc).__name__}: {exc}".split())[:MAX_FAILURE_DETAIL]


class RuntimeResult(StrictModel):
    status: str
    reason_code: str
    result: AdapterResult | None = None
    event_hashes: tuple[str, ...] = ()
    #: Bounded, redacted account of a ``failed`` result. Diagnostic only: it is outside the score
    #: hash, so the wording of an exception can never move a verdict.
    detail: str | None = None

    @computed_field  # type: ignore[prop-decorator]
    @property
    def score_hash(self) -> str:
        result = (
            {"status": self.result.status, "data": self.result.data}
            if self.result is not None
            else None
        )
        return digest_data(
            {"status": self.status, "reason_code": self.reason_code, "result": result}
        )


class SafetyRuntime:
    def __init__(
        self,
        *,
        verifier: ManifestVerifier,
        policy: PolicyEngine,
        budgets: BudgetLedger,
        kill_switch: KillSwitch,
        credential_broker: CredentialBroker,
        redactor: Redactor,
        adapter: Adapter,
        ledger: EvidenceLedger,
        clock: Callable[[], datetime] | None = None,
        shadow: bool = False,
        admission: ApprovalAdmission | None = None,
        loop_guard: LoopGuardGrant | None = None,
    ) -> None:
        self.verifier = verifier
        self.policy = policy
        self.budgets = budgets
        self.kill_switch = kill_switch
        self.credential_broker = credential_broker
        self.redactor = redactor
        self.adapter = adapter
        self.ledger = ledger
        self.clock = clock or (lambda: datetime.now(UTC))
        #: Shadow mode (WP5.1): decide every action in full and dispatch none. Either this flag or
        #: a shadow manifest puts the runtime in shadow; nothing can take it out again for a run.
        self.shadow = shadow
        #: Capability-increase admission for manifest 1.5 (``control.approvals``). Without it, a
        #: 1.5 manifest is refused: an unconfigured check is not a passed check.
        self.admission = admission
        #: The runaway-loop detector (ADR 0018), one per signed manifest digest. Disarmed -- and
        #: silent -- unless the manifest signs ``phase5.loop_guard``.
        self._loop_guards: dict[str, LoopGuard] = {}
        #: Thresholds from another signed document the host verified before building this
        #: runtime -- the evaluation matrix spec, whose trials run on manifests 1.3 that cannot
        #: carry the grant. Combined with a manifest grant by taking the stricter of each limit.
        self.host_loop_guard = loop_guard
        self.scenario_id: str | None = None
        self.scenario_version: str | None = None
        self.stage: str | None = None

    async def run(
        self,
        manifest: AuthorizationManifest,
        action: ActionRequest,
        *,
        run_id: str,
        trace_id: str,
    ) -> RuntimeResult:
        manifest_digest = manifest.manifest_digest()
        policy_digest = getattr(self.policy, "policy_digest", "0" * 64)
        action_digest = action.digest()
        event_hashes: list[str] = []
        reservation: Reservation | None = None
        effective_redactor = self.redactor

        try:
            self.verifier.verify(manifest, now=self.clock())
            if manifest.phase5 is not None:
                self._admit_capabilities(manifest)
        except ManifestError as exc:
            event = self._record(
                run_id,
                trace_id,
                EventKind.ADMISSION,
                manifest_digest,
                policy_digest,
                action_digest,
                "deny",
                exc.reason_code,
                redactor=effective_redactor,
            )
            return RuntimeResult(
                status="denied", reason_code=exc.reason_code, event_hashes=(event.event_hash or "",)
            )

        guard = self.loop_guard(manifest, digest=manifest_digest)
        # Every target-plane action from every source -- plan node, model intent, attacker
        # proposal -- reaches this line. The control plane is exempt (``CONTROL_ADAPTER``).
        watched = guard.armed and action.adapter != CONTROL_ADAPTER
        fingerprint = action_fingerprint(action) if watched else ""
        if watched:
            refused = self._loop_boundary(
                guard, fingerprint, manifest, run_id, trace_id, manifest_digest, action_digest
            )
            if refused is not None:
                return refused

        decision = self.policy.evaluate(manifest, action)
        policy_event = self._record(
            run_id,
            trace_id,
            EventKind.POLICY,
            manifest_digest,
            decision.policy_digest,
            action_digest,
            decision.effect,
            decision.reason_code,
            {"arguments": action.arguments} if action.arguments is not None else None,
            redactor=effective_redactor,
        )
        event_hashes.append(policy_event.event_hash or "")
        if not decision.permitted:
            if watched and not self.is_shadow(manifest):
                self._loop_outcome(
                    guard, None, run_id, trace_id, manifest_digest, action_digest, event_hashes
                )
            return RuntimeResult(
                status="denied",
                reason_code=decision.reason_code,
                event_hashes=tuple(event_hashes),
            )

        try:
            await self.kill_switch.ensure_running()
            reservation = await self.budgets.reserve(action.budget)
        except (KernelStopped, BudgetError) as exc:
            return self._denied_with_event(
                run_id,
                trace_id,
                manifest_digest,
                decision.policy_digest,
                action_digest,
                exc.reason_code,
                event_hashes,
                effective_redactor,
            )

        if self.is_shadow(manifest):
            # Shadow: admission, policy, kill switch, and the budget reservation above all ran
            # exactly as for an execution. The adapter is never reached because nothing here
            # dispatches to it -- there is no task, no credential resolution, no target guard.
            # The reservation is finalized as consumed, so a shadow run exhausts its budget
            # where an execution would have.
            try:
                event = self._record(
                    run_id,
                    trace_id,
                    EventKind.SHADOW_SUPPRESSED,
                    manifest_digest,
                    decision.policy_digest,
                    action_digest,
                    "suppressed",
                    "SHADOW_SUPPRESSED",
                    {
                        "would_apply": decision.effect.value,
                        "policy_reason": decision.reason_code,
                        "adapter": action.adapter,
                        "operation": action.operation,
                        "side_effect": action.side_effect.value,
                        "budget": action.budget.model_dump(mode="json"),
                    },
                    redactor=effective_redactor,
                    schema_version=SHADOW_EVENT_SCHEMA,
                )
            finally:
                await self.budgets.finalize(reservation)
            event_hashes.append(event.event_hash or "")
            return RuntimeResult(
                status="suppressed",
                reason_code="SHADOW_SUPPRESSED",
                event_hashes=tuple(event_hashes),
            )

        next_hop = 0
        detail: str | None = None
        #: Whether this outcome counts toward the no-progress check. A stopped kernel or a
        #: manifest that stopped verifying ends the run on its own and is not a loop.
        loop_counted = False

        async def authorize_subresource(observation: TargetObservation) -> None:
            """Route-level origin authorization for a browser subresource.

            Decided before the request is sent, from signed data only: the request is permitted
            when its URL falls inside the action's own signed asset or its origin is a signed
            subresource origin. Either way it is charged to the run budget and recorded, so a
            blocked request is never silently dropped.
            """
            try:
                self.verifier.verify(manifest, now=self.clock())
                expected = match_scope(action.target, manifest.assets)
                canonical = canonicalize_url(observation.url)
                origin = f"{canonical.scheme}://{canonical.host}:{canonical.port}"
                reason = "SUBRESOURCE_PERMITTED"
                try:
                    observed_scope = match_scope(
                        ActionTarget(url=observation.url, tenant_id=action.target.tenant_id),
                        manifest.assets,
                    )
                    same_asset = observed_scope.asset_id == expected.asset_id
                except TargetError as exc:
                    same_asset = False
                    reason = exc.reason_code
                signed_origins = manifest.phase2.subresource_origins if manifest.phase2 else ()
                permitted = same_asset or origin in signed_origins
                if not permitted and reason == "SUBRESOURCE_PERMITTED":
                    reason = "SUBRESOURCE_ORIGIN_NOT_SIGNED"
                await self.budgets.charge(BudgetRequest(requests=1, records=0))
                event = self._record(
                    run_id,
                    trace_id,
                    EventKind.POLICY,
                    manifest_digest,
                    decision.policy_digest,
                    action_digest,
                    "permit" if permitted else "deny",
                    reason,
                    {"url": observation.url, "origin": origin, "kind": "subresource"},
                    redactor=effective_redactor,
                )
                event_hashes.append(event.event_hash or "")
                if not permitted:
                    raise SubresourceDenied(reason)
            except (ManifestError, TargetError, BudgetError) as exc:
                raise BoundaryDenied(exc.reason_code) from exc

        async def authorize_model(observation: TargetObservation) -> None:
            """Authorize a model-plane call before any connection is made.

            The model plane is separate from the target plane (ADR 0008): a model endpoint is
            never a signed target asset, so this never consults ``manifest.assets`` for permission.
            It authorizes an exact signed origin from ``phase3.model_assets``, refuses a
            resolution that lands on a signed target endpoint -- which is how a rebind would try
            to aim a model call at the fixture -- and charges the request either way, so a denied
            call is recorded and paid for rather than silently dropped.
            """
            try:
                self.verifier.verify(manifest, now=self.clock())
                grants = manifest.phase3
                canonical = canonicalize_url(observation.url)
                origin = f"{canonical.scheme}://{canonical.host}:{canonical.port}"
                signed = grants.model_assets if grants is not None else frozenset()
                target_endpoints = {
                    (address, asset.port)
                    for asset in manifest.assets
                    for address in asset.allowed_resolved_addresses
                }
                rebound = any(
                    (address, canonical.port) in target_endpoints
                    for address in observation.resolved_addresses
                )
                permitted = origin in signed and not rebound
                reason = "MODEL_ENDPOINT_PERMITTED"
                if origin not in signed:
                    reason = "MODEL_ENDPOINT_NOT_SIGNED"
                elif rebound:
                    reason = "MODEL_ENDPOINT_RESOLVES_TO_TARGET"
                await self.budgets.charge(BudgetRequest(requests=1, records=0))
                event = self._record(
                    run_id,
                    trace_id,
                    EventKind.POLICY,
                    manifest_digest,
                    decision.policy_digest,
                    action_digest,
                    "permit" if permitted else "deny",
                    reason,
                    {
                        "url": observation.url,
                        "origin": origin,
                        "kind": "model",
                        "resolved_addresses": [
                            str(address) for address in observation.resolved_addresses
                        ],
                    },
                    redactor=effective_redactor,
                )
                event_hashes.append(event.event_hash or "")
                if not permitted:
                    raise BoundaryDenied(reason)
            except (ManifestError, TargetError, BudgetError) as exc:
                raise BoundaryDenied(exc.reason_code) from exc

        async def authorize_target(observation: TargetObservation) -> None:
            nonlocal next_hop
            if observation.kind == "subresource":
                await authorize_subresource(observation)
                return
            if observation.kind == "model":
                await authorize_model(observation)
                return
            try:
                if observation.hop_index != next_hop:
                    raise BoundaryDenied("INVALID_REDIRECT_SEQUENCE")
                self.verifier.verify(manifest, now=self.clock())
                observed_action = action.model_copy(
                    update={"target": action.target.model_copy(update={"url": observation.url})}
                )
                observed_decision = self.policy.evaluate(manifest, observed_action)
                if not observed_decision.permitted:
                    raise BoundaryDenied(observed_decision.reason_code)
                validate_observation(observation, action.target, manifest.assets)
                next_hop += 1
                event = self._record(
                    run_id,
                    trace_id,
                    EventKind.POLICY,
                    manifest_digest,
                    observed_decision.policy_digest,
                    observed_action.digest(),
                    "permit",
                    "TARGET_OBSERVED",
                    {
                        "hop_index": observation.hop_index,
                        "url": observation.url,
                        "resolved_addresses": [
                            str(address) for address in observation.resolved_addresses
                        ],
                    },
                    redactor=effective_redactor,
                )
                event_hashes.append(event.event_hash or "")
            except (ManifestError, TargetError) as exc:
                raise BoundaryDenied(exc.reason_code) from exc

        async def adapter_activity() -> AdapterResult:
            nonlocal effective_redactor
            self.verifier.verify(manifest, now=self.clock())
            if manifest.phase5 is not None:
                self._admit_capabilities(manifest)
            latest_decision = self.policy.evaluate(manifest, action)
            if not latest_decision.permitted:
                raise BoundaryDenied(latest_decision.reason_code)
            await self.adapter.preflight(action)
            credential = (
                self.credential_broker.resolve(action.credential_handle)
                if action.credential_handle is not None
                else None
            )
            if credential is not None:
                effective_redactor = self.redactor.with_secrets((credential,))
            adapter_result = await self.adapter.execute(
                action,
                credential=credential,
                authorize_target=authorize_target,
            )
            if not await self.adapter.postcondition(action, adapter_result):
                raise RuntimeError("adapter postcondition failed")
            return adapter_result

        try:
            remaining = self.budgets.remaining_wall_time
            if remaining <= 0:
                raise TimeoutError
            task = await self.kill_switch.spawn(adapter_activity)
            async with asyncio.timeout(remaining):
                adapter_result = cast(AdapterResult, await task)
            safe_result = adapter_result.model_copy(
                update={"data": effective_redactor.redact(adapter_result.data)}
            )
            event = self._record(
                run_id,
                trace_id,
                EventKind.RESULT,
                manifest_digest,
                decision.policy_digest,
                action_digest,
                "permit",
                "COMPLETED",
                {
                    "status": safe_result.status,
                    "data": safe_result.data,
                    **({"latency_ms": safe_result.latency_ms} if self.scenario_id else {}),
                },
                redactor=effective_redactor,
            )
            event_hashes.append(event.event_hash or "")
            if watched:
                # The action completed and its result stands; a no-progress trip here latches
                # the guard so the run's next target-plane action is refused.
                self._loop_outcome(
                    guard,
                    outcome_digest(
                        fingerprint, action.side_effect, safe_result.status, safe_result.data
                    ),
                    run_id,
                    trace_id,
                    manifest_digest,
                    action_digest,
                    event_hashes,
                )
            return RuntimeResult(
                status="completed",
                reason_code="COMPLETED",
                result=safe_result,
                event_hashes=tuple(event_hashes),
            )
        except asyncio.CancelledError:
            # The wall-time deadline cancels the awaiting task; asyncio.timeout normally reports
            # that as TimeoutError, but under scheduling contention the cancellation can surface
            # here directly. Classify by cause: an exhausted wall-time budget with the kernel still
            # running is a wall-time timeout, never an operator/kill-switch cancellation.
            if (
                self.kill_switch.state == KernelState.RUNNING
                and self.budgets.remaining_wall_time <= 0
            ):
                reason_code = "WALL_TIME_EXCEEDED"
                status = "denied"
                kind = EventKind.BUDGET
            else:
                reason_code = "CANCELLED"
                status = "cancelled"
                kind = EventKind.TERMINATION
        except TimeoutError:
            reason_code = "WALL_TIME_EXCEEDED"
            status = "denied"
            kind = EventKind.BUDGET
        except Exception as exc:
            reason_code = str(getattr(exc, "reason_code", "EXECUTION_FAILED"))
            status = (
                "denied"
                if isinstance(exc, (BoundaryDenied, KernelStopped, ManifestError))
                else "failed"
            )
            kind = EventKind.RESULT
            loop_counted = not isinstance(exc, (KernelStopped, ManifestError))
            if status == "failed":
                detail = effective_redactor.redact(failure_detail(exc))
        finally:
            if reservation is not None:
                await self.budgets.finalize(reservation)

        event = self._record(
            run_id,
            trace_id,
            kind,
            manifest_digest,
            decision.policy_digest,
            action_digest,
            "deny",
            reason_code,
            {"detail": detail} if detail is not None else None,
            redactor=effective_redactor,
        )
        event_hashes.append(event.event_hash or "")
        if watched and loop_counted:
            # Denied by the target guard or failed at execution: nothing changed. Cancellation,
            # wall time, a stopped kernel, and an invalid manifest end the run on their own.
            self._loop_outcome(
                guard, None, run_id, trace_id, manifest_digest, action_digest, event_hashes
            )
        return RuntimeResult(
            status=status,
            reason_code=reason_code,
            event_hashes=tuple(event_hashes),
            detail=detail,
        )

    def loop_guard(
        self, manifest: AuthorizationManifest, *, digest: str | None = None
    ) -> LoopGuard:
        """The runaway-loop detector for ``manifest``, armed only by its signed grant."""
        digest = digest or manifest.manifest_digest()
        guard = self._loop_guards.get(digest)
        if guard is None:
            signed = manifest.phase5.loop_guard if manifest.phase5 is not None else None
            guard = self._loop_guards[digest] = LoopGuard(
                stricter_grant(signed, self.host_loop_guard)
            )
        return guard

    @property
    def loop_tripped(self) -> bool:
        """True once any detector of this runtime has latched: the run must end."""
        return any(guard.tripped is not None for guard in self._loop_guards.values())

    def refused_step(
        self,
        manifest: AuthorizationManifest,
        step: Step | str,
        reason: str,
        *,
        run_id: str,
        trace_id: str,
    ) -> bool:
        """Count a model- or attacker-originated attempt that never became an action.

        ``step`` is a typed step the plan compiler refused, or the name of a tool intent the
        agent adapter rejected before it was typed at all. Either is still an action boundary: a
        model that asks for the same forbidden tool call turn after turn is the commonest
        runaway loop, and it never reaches :meth:`run`. True when the detector has latched and
        the run must end.
        """
        guard = self.loop_guard(manifest)
        if not guard.armed:
            return False
        shadow = self.is_shadow(manifest)
        if guard.tripped is not None and not shadow:
            return True
        fingerprint = (
            step_fingerprint(step) if isinstance(step, Step) else rejected_fingerprint(step)
        )
        trip = guard.boundary(fingerprint, self.stage)
        if trip is None and not shadow:
            trip = guard.observe(None)
        if trip is None:
            return False
        self._record_trip(
            trip,
            run_id,
            trace_id,
            manifest.manifest_digest(),
            step.digest() if isinstance(step, Step) else fingerprint,
            shadow=shadow,
            extra={"refused": reason[:64]},
        )
        if shadow:
            return False
        guard.latch(trip)
        return True

    def _loop_boundary(
        self,
        guard: LoopGuard,
        fingerprint: str,
        manifest: AuthorizationManifest,
        run_id: str,
        trace_id: str,
        manifest_digest: str,
        action_digest: str,
    ) -> RuntimeResult | None:
        """Refuse a latched run's action, or this action if it is the N-th repetition.

        In shadow nothing is refused: a would-be trip is recorded and the walk goes on.
        """
        shadow = self.is_shadow(manifest)
        trip = guard.tripped if not shadow else None
        latched = trip is not None
        if trip is None:
            trip = guard.boundary(fingerprint, self.stage)
            if trip is None:
                return None
        event = self._record_trip(
            trip,
            run_id,
            trace_id,
            manifest_digest,
            action_digest,
            shadow=shadow,
            extra={"latched": True} if latched else None,
        )
        if shadow:
            return None
        guard.latch(trip)
        return RuntimeResult(
            status="denied",
            reason_code=RUNAWAY_LOOP_DETECTED,
            event_hashes=(event.event_hash or "",),
        )

    def _loop_outcome(
        self,
        guard: LoopGuard,
        outcome: str | None,
        run_id: str,
        trace_id: str,
        manifest_digest: str,
        action_digest: str,
        event_hashes: list[str],
    ) -> None:
        """Record what the action last counted changed; latch on the K-th unchanged one."""
        trip = guard.observe(outcome)
        if trip is None:
            return
        guard.latch(trip)
        event = self._record_trip(
            trip, run_id, trace_id, manifest_digest, action_digest, shadow=False
        )
        event_hashes.append(event.event_hash or "")

    def _record_trip(
        self,
        trip: LoopTrip,
        run_id: str,
        trace_id: str,
        manifest_digest: str,
        action_digest: str,
        *,
        shadow: bool,
        extra: dict[str, object] | None = None,
    ) -> EvidenceEvent:
        """The detection as a ``POLICY`` event, so the audit export's decision record lists it."""
        return self._record(
            run_id,
            trace_id,
            EventKind.POLICY,
            manifest_digest,
            getattr(self.policy, "policy_digest", "0" * 64),
            action_digest,
            "would-deny" if shadow else "deny",
            RUNAWAY_LOOP_WOULD_TRIP if shadow else RUNAWAY_LOOP_DETECTED,
            {**trip.evidence(), **(extra or {})},
            redactor=self.redactor,
            schema_version=SHADOW_EVENT_SCHEMA if shadow else None,
        )

    def is_shadow(self, manifest: AuthorizationManifest) -> bool:
        """True when this action must be decided and not dispatched."""
        return self.shadow or (manifest.phase5 is not None and manifest.phase5.run_mode == "shadow")

    def _admit_capabilities(self, manifest: AuthorizationManifest) -> AdmissionDecision:
        """Refuse a 1.5 manifest whose capability increase is not covered (ApprovalRefused)."""
        if self.admission is None:
            raise ApprovalRefused(
                "APPROVAL_ADMISSION_UNCONFIGURED",
                "a manifest 1.5 needs the approved baseline to be admitted",
            )
        return self.admission.admit(manifest, now=self.clock())

    def admit(
        self, manifest: AuthorizationManifest, *, run_id: str, trace_id: str
    ) -> AdmissionDecision | None:
        """Run-level capability admission, recorded as one ``ADMISSION`` event.

        ``None`` for a manifest before 1.5, with nothing recorded, so a v1 ledger is unchanged.
        For 1.5 the decision -- admitted with its delta, or refused with its reason -- is
        evidence either way, and a refusal raises :class:`ApprovalRefused` after it is recorded.
        """
        if manifest.phase5 is None:
            return None
        try:
            decision = self._admit_capabilities(manifest)
        except ApprovalRefused as exc:
            self._record(
                run_id,
                trace_id,
                EventKind.ADMISSION,
                manifest.manifest_digest(),
                getattr(self.policy, "policy_digest", "0" * 64),
                None,
                "deny",
                exc.reason_code,
                {"detail": str(exc)[:MAX_FAILURE_DETAIL]},
                redactor=self.redactor,
            )
            raise
        self._record(
            run_id,
            trace_id,
            EventKind.ADMISSION,
            manifest.manifest_digest(),
            getattr(self.policy, "policy_digest", "0" * 64),
            None,
            "permit",
            decision.reason_code,
            decision.evidence(),
            redactor=self.redactor,
        )
        return decision

    def _denied_with_event(
        self,
        run_id: str,
        trace_id: str,
        manifest_digest: str,
        policy_digest: str,
        action_digest: str,
        reason_code: str,
        event_hashes: list[str],
        redactor: Redactor,
    ) -> RuntimeResult:
        event = self._record(
            run_id,
            trace_id,
            EventKind.BUDGET,
            manifest_digest,
            policy_digest,
            action_digest,
            "deny",
            reason_code,
            redactor=redactor,
        )
        return RuntimeResult(
            status="denied",
            reason_code=reason_code,
            event_hashes=(*event_hashes, event.event_hash or ""),
        )

    def _record(
        self,
        run_id: str,
        trace_id: str,
        kind: EventKind,
        manifest_digest: str,
        policy_digest: str,
        action_digest: str | None,
        decision: str,
        reason_code: str,
        data: dict[str, object] | None = None,
        *,
        redactor: Redactor,
        schema_version: str | None = None,
    ) -> EvidenceEvent:
        event = EvidenceEvent(
            schema_version=schema_version or ("1.1.0" if self.scenario_id else None),
            scenario_id=self.scenario_id,
            scenario_version=self.scenario_version,
            stage=self.stage,
            component_version="runtime-v1" if self.scenario_id else None,
            run_id=run_id,
            trace_id=trace_id,
            sequence=0,
            timestamp=self.clock(),
            actor="safety-kernel",
            kind=kind,
            manifest_digest=manifest_digest,
            policy_digest=policy_digest,
            action_digest=action_digest,
            decision=decision,
            reason_code=reason_code,
            data=redactor.redact(data or {}),
        )
        return self.ledger.append(event)
