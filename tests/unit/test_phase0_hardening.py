from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from purpleloop.adapters import (
    AdapterResult,
    MockReadAdapter,
    OfflineModelStore,
    OfflineResponseMissing,
)
from purpleloop.control import (
    BudgetError,
    BudgetLedger,
    DefaultDenyPolicy,
    InMemoryRevocationProvider,
    KernelStopped,
    KillSwitch,
    ManifestError,
    ManifestVerifier,
)
from purpleloop.control.manifest import sign_manifest
from purpleloop.runtime import EvidenceLedger, compare_replays
from purpleloop.schemas import (
    ActionRequest,
    AuthorizationManifest,
    BudgetLimits,
    BudgetRequest,
    EventKind,
    EvidenceEvent,
    ExactExclusion,
    TargetObservation,
)


@pytest.mark.parametrize(
    "change",
    [
        {"url": "http://fixture.local:8080/records/record-2"},
        {"url": "http://fixture.local:8080/records/record-1?resource=record-2"},
        {"url": "http://fixture.local:8080/records/%2e%2e/record-1"},
    ],
)
def test_tool_schema_binds_resource_to_canonical_url(
    manifest: AuthorizationManifest,
    action: ActionRequest,
    change: dict[str, object],
) -> None:
    target = action.target.model_copy(update=change)
    decision = DefaultDenyPolicy().evaluate(manifest, action.model_copy(update={"target": target}))
    assert not decision.permitted
    assert decision.reason_code in {"TOOL_SCHEMA_MISMATCH", "PATH_TRAVERSAL"}


def test_exact_exclusion_takes_precedence(
    manifest: AuthorizationManifest, action: ActionRequest
) -> None:
    excluded = manifest.model_copy(
        update={"exact_exclusions": (ExactExclusion(tenant_id="tenant-a", resource_id="record-1"),)}
    )
    decision = DefaultDenyPolicy().evaluate(excluded, action)
    assert decision.reason_code == "EXACT_EXCLUSION"


def test_ambiguous_asset_scope_fails_closed(
    manifest: AuthorizationManifest, action: ActionRequest
) -> None:
    ambiguous = manifest.model_copy(update={"assets": (*manifest.assets, manifest.assets[0])})
    decision = DefaultDenyPolicy().evaluate(ambiguous, action)
    assert decision.reason_code == "AMBIGUOUS_SCOPE"


def test_revocation_outage_fails_closed(
    manifest: AuthorizationManifest, private_key: Ed25519PrivateKey
) -> None:
    provider = InMemoryRevocationProvider(available=False)
    verifier = ManifestVerifier({"test-key": private_key.public_key()}, revocations=provider)
    with pytest.raises(ManifestError) as error:
        verifier.verify(manifest)
    assert error.value.reason_code == "REVOCATION_UNAVAILABLE"


@pytest.mark.asyncio
async def test_budget_rejects_duplicate_finalize_and_excessive_refund() -> None:
    ledger = BudgetLedger(BudgetLimits(requests=2, records=2))
    reservation = await ledger.reserve(BudgetRequest(requests=1, records=1))
    with pytest.raises(BudgetError):
        await ledger.finalize(reservation, unused=BudgetRequest(requests=2, records=1))
    await ledger.finalize(reservation)
    with pytest.raises(BudgetError):
        await ledger.finalize(reservation)


@pytest.mark.asyncio
async def test_wall_time_is_enforced_during_adapter_activity(
    manifest: AuthorizationManifest,
    action: ActionRequest,
    private_key: Ed25519PrivateKey,
    runtime_factory: Any,
) -> None:
    short = manifest.model_copy(
        update={
            "budgets": manifest.budgets.model_copy(update={"wall_time_seconds": 0.05}),
            "signature": "",
        }
    )
    signed = sign_manifest(short, private_key)
    runtime, _, _ = runtime_factory(manifest=signed, adapter=MockReadAdapter(delay_seconds=30))
    result = await runtime.run(signed, action, run_id="wall-time", trace_id="wall-time-trace")
    assert result.status == "denied"
    assert result.reason_code == "WALL_TIME_EXCEEDED"


@pytest.mark.asyncio
async def test_spawn_after_termination_never_starts_work() -> None:
    switch = KillSwitch()
    started = False

    async def work() -> object:
        nonlocal started
        started = True
        return object()

    await switch.terminate()
    with pytest.raises(KernelStopped):
        await switch.spawn(work)
    assert not started


def test_offline_model_store_has_no_fallback() -> None:
    fixture = Path(__file__).parents[1] / "fixtures" / "model_responses" / "phase0.json"
    store = OfflineModelStore(fixture)
    response = store.complete(
        model="offline-model",
        profile="deterministic",
        request={"messages": [{"role": "user", "content": "phase0"}]},
    )
    assert response.response == "Synthetic offline response."
    with pytest.raises(OfflineResponseMissing):
        store.complete(
            model="offline-model",
            profile="deterministic",
            request={"messages": [{"role": "user", "content": "unknown"}]},
        )


def test_concurrent_ledger_appends_remain_a_single_chain(tmp_path: Path) -> None:
    ledger = EvidenceLedger(tmp_path / "concurrent.jsonl")

    def append(index: int) -> None:
        ledger.append(
            EvidenceEvent(
                run_id="concurrent-run",
                trace_id="concurrent-trace",
                sequence=0,
                timestamp=datetime(2026, 1, 1, tzinfo=UTC),
                actor="test",
                kind=EventKind.RESULT,
                manifest_digest="0" * 64,
                policy_digest="1" * 64,
                decision="permit",
                reason_code=f"EVENT_{index}",
            )
        )

    with ThreadPoolExecutor(max_workers=8) as executor:
        list(executor.map(append, range(20)))
    assert len(ledger.verify()) == 20


def test_replay_hash_ignores_run_clock_and_latency() -> None:
    base = EvidenceEvent(
        run_id="run-one",
        trace_id="trace-one",
        sequence=0,
        timestamp=datetime(2026, 1, 1, tzinfo=UTC),
        actor="test",
        kind=EventKind.RESULT,
        manifest_digest="0" * 64,
        policy_digest="1" * 64,
        decision="permit",
        reason_code="COMPLETED",
        data={"latency_ms": 1.0, "value": "same"},
    )
    changed = base.model_copy(
        update={
            "run_id": "run-two",
            "trace_id": "trace-two",
            "timestamp": base.timestamp + timedelta(days=1),
            "data": {"latency_ms": 999.0, "value": "same"},
        }
    )
    assert compare_replays([base], [changed], first_score_hash="a" * 64, second_score_hash="a" * 64)


class SecretEchoAdapter:
    name = "mock_read"

    async def preflight(self, action: ActionRequest) -> None:
        return

    async def execute(
        self,
        action: ActionRequest,
        *,
        credential: str | None,
        authorize_target: Any,
    ) -> AdapterResult:
        await authorize_target(
            TargetObservation(
                url=action.target.url,
                resolved_addresses=("127.0.0.1",),
                hop_index=0,
            )
        )
        return AdapterResult(
            status="success",
            data={
                "echo": credential,
                "Authorization": f"Bearer {credential}",
            },
            latency_ms=0,
        )

    async def cancel(self) -> None:
        return

    async def postcondition(self, action: ActionRequest, result: AdapterResult) -> bool:
        return True


@pytest.mark.asyncio
async def test_resolved_credentials_are_always_redacted(
    manifest: AuthorizationManifest,
    action: ActionRequest,
    runtime_factory: Any,
) -> None:
    runtime, _, ledger = runtime_factory(manifest=manifest, adapter=SecretEchoAdapter())
    result = await runtime.run(manifest, action, run_id="secret-run", trace_id="secret-trace")
    rendered = result.model_dump_json() + ledger.path.read_text(encoding="utf-8")
    assert "CREDENTIAL-SECRET" not in rendered
    assert "[REDACTED]" in rendered


class PolicyFlipAdapter(MockReadAdapter):
    def __init__(self, policy: DefaultDenyPolicy) -> None:
        super().__init__()
        self.policy = policy

    async def preflight(self, action: ActionRequest) -> None:
        await super().preflight(action)
        self.policy.stale = True


@pytest.mark.asyncio
async def test_policy_becoming_stale_at_boundary_denies_before_io(
    manifest: AuthorizationManifest,
    action: ActionRequest,
    runtime_factory: Any,
) -> None:
    policy = DefaultDenyPolicy()
    adapter = PolicyFlipAdapter(policy)
    runtime, _, _ = runtime_factory(
        manifest=manifest,
        adapter=adapter,
        policy=policy,
    )
    result = await runtime.run(manifest, action, run_id="stale-run", trace_id="stale-trace")
    assert result.reason_code == "POLICY_STALE"
    assert adapter.invocations == 0


class RevocationFlipAdapter(MockReadAdapter):
    def __init__(self, provider: InMemoryRevocationProvider, manifest_digest: str) -> None:
        super().__init__()
        self.provider = provider
        self.manifest_digest = manifest_digest

    async def preflight(self, action: ActionRequest) -> None:
        await super().preflight(action)
        self.provider.revoked_digests.add(self.manifest_digest)


@pytest.mark.asyncio
async def test_revocation_change_at_boundary_denies_before_io(
    manifest: AuthorizationManifest,
    action: ActionRequest,
    private_key: Ed25519PrivateKey,
    runtime_factory: Any,
) -> None:
    provider = InMemoryRevocationProvider()
    verifier = ManifestVerifier(
        {"test-key": private_key.public_key()},
        revocations=provider,
    )
    adapter = RevocationFlipAdapter(provider, manifest.manifest_digest())
    runtime, _, _ = runtime_factory(
        manifest=manifest,
        adapter=adapter,
        verifier=verifier,
    )
    result = await runtime.run(manifest, action, run_id="revoked-run", trace_id="revoked-trace")
    assert result.reason_code == "REVOKED_MANIFEST"
    assert adapter.invocations == 0


class SecretFailureAdapter(SecretEchoAdapter):
    async def execute(
        self,
        action: ActionRequest,
        *,
        credential: str | None,
        authorize_target: Any,
    ) -> AdapterResult:
        await authorize_target(
            TargetObservation(
                url=action.target.url,
                resolved_addresses=("127.0.0.1",),
                hop_index=0,
            )
        )
        raise RuntimeError(f"adapter failed with {credential}")


@pytest.mark.asyncio
async def test_exception_text_cannot_leak_credentials(
    manifest: AuthorizationManifest,
    action: ActionRequest,
    runtime_factory: Any,
) -> None:
    runtime, _, ledger = runtime_factory(
        manifest=manifest,
        adapter=SecretFailureAdapter(),
    )
    result = await runtime.run(
        manifest,
        action,
        run_id="secret-failure",
        trace_id="secret-failure-trace",
    )
    rendered = result.model_dump_json() + ledger.path.read_text(encoding="utf-8")
    assert result.status == "failed"
    assert "CREDENTIAL-SECRET" not in rendered
