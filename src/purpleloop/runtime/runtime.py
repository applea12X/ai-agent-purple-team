from __future__ import annotations

import asyncio
from collections.abc import Callable
from datetime import UTC, datetime
from typing import cast

from pydantic import computed_field

from purpleloop.adapters.base import Adapter, AdapterResult
from purpleloop.control.budgets import BudgetError, BudgetLedger, Reservation
from purpleloop.control.credentials import CredentialBroker
from purpleloop.control.kill_switch import KernelStopped, KillSwitch
from purpleloop.control.manifest import ManifestError, ManifestVerifier
from purpleloop.control.policy import PolicyEngine
from purpleloop.control.redaction import Redactor
from purpleloop.control.targets import TargetError, validate_observation
from purpleloop.runtime.ledger import EvidenceLedger
from purpleloop.schemas.action import ActionRequest, TargetObservation
from purpleloop.schemas.authorization import AuthorizationManifest
from purpleloop.schemas.common import StrictModel, digest_data
from purpleloop.schemas.event import EventKind, EvidenceEvent


class BoundaryDenied(RuntimeError):
    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


class RuntimeResult(StrictModel):
    status: str
    reason_code: str
    result: AdapterResult | None = None
    event_hashes: tuple[str, ...] = ()

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

        next_hop = 0

        async def authorize_target(observation: TargetObservation) -> None:
            nonlocal next_hop
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
            return RuntimeResult(
                status="completed",
                reason_code="COMPLETED",
                result=safe_result,
                event_hashes=tuple(event_hashes),
            )
        except asyncio.CancelledError:
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
            redactor=effective_redactor,
        )
        event_hashes.append(event.event_hash or "")
        return RuntimeResult(
            status=status,
            reason_code=reason_code,
            event_hashes=tuple(event_hashes),
        )

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
        action_digest: str,
        decision: str,
        reason_code: str,
        data: dict[str, object] | None = None,
        *,
        redactor: Redactor,
    ) -> EvidenceEvent:
        event = EvidenceEvent(
            schema_version="1.1.0" if self.scenario_id else None,
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
