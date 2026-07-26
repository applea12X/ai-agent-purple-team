from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from purpleloop.adapters import Adapter, MockReadAdapter
from purpleloop.control import (
    BudgetLedger,
    DefaultDenyPolicy,
    InMemoryCredentialBroker,
    KillSwitch,
    ManifestVerifier,
    Redactor,
)
from purpleloop.control.manifest import sign_manifest
from purpleloop.runtime import EvidenceLedger, SafetyRuntime
from purpleloop.schemas import (
    ActionRequest,
    ActionTarget,
    AssetScope,
    AuthorizationManifest,
    BudgetLimits,
    BudgetRequest,
    SideEffectClass,
)

FIXED_NOW = datetime(2026, 7, 25, 12, 0, tzinfo=UTC)


@pytest.fixture
def private_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


@pytest.fixture
def manifest(private_key: Ed25519PrivateKey) -> AuthorizationManifest:
    unsigned = AuthorizationManifest(
        engagement_id="engagement-1",
        owner="owner-1",
        approvers=("approver-1",),
        key_id="test-key",
        issued_at=datetime(2026, 1, 1, tzinfo=UTC),
        valid_from=datetime(2026, 1, 2, tzinfo=UTC),
        valid_until=datetime(2027, 1, 1, tzinfo=UTC),
        assets=(
            AssetScope(
                asset_id="fixture",
                scheme="http",
                host="fixture.local",
                port=8080,
                path_prefix="/",
                tenant_ids=frozenset({"tenant-a"}),
                resource_ids=frozenset({"record-1"}),
                allowed_resolved_addresses=frozenset({"127.0.0.1"}),
            ),
        ),
        allowed_adapters=frozenset({"mock_read"}),
        allowed_operations=frozenset({"health.read", "record.read"}),
        denied_operations=frozenset(),
        allowed_methods=frozenset({"GET"}),
        credential_handles=frozenset({"fixture-credential"}),
        credential_scopes={"fixture-credential": frozenset({"health.read", "record.read"})},
        egress_hosts=frozenset({"fixture.local"}),
        budgets=BudgetLimits(
            requests=20,
            records=20,
            retries=2,
            concurrency=4,
            wall_time_seconds=30,
        ),
        synthetic_secrets=("CANARY-SECRET",),
        signature="",
    )
    return sign_manifest(unsigned, private_key)


@pytest.fixture
def action() -> ActionRequest:
    return ActionRequest(
        action_id="action-1",
        adapter="mock_read",
        operation="record.read",
        method="GET",
        target=ActionTarget(
            url="http://fixture.local:8080/records/record-1",
            tenant_id="tenant-a",
            resource_id="record-1",
        ),
        side_effect=SideEffectClass.READ,
        credential_handle="fixture-credential",
        idempotency_key="idem-1",
        budget=BudgetRequest(requests=1, records=1),
    )


@pytest.fixture
def runtime_factory(
    tmp_path: Path,
    private_key: Ed25519PrivateKey,
) -> Callable[..., tuple[SafetyRuntime, MockReadAdapter, EvidenceLedger]]:
    counter = 0

    def factory(
        *,
        manifest: AuthorizationManifest,
        adapter: Adapter | None = None,
        policy: DefaultDenyPolicy | None = None,
        kill_switch: KillSwitch | None = None,
        verifier: ManifestVerifier | None = None,
    ) -> tuple[SafetyRuntime, Adapter, EvidenceLedger]:
        nonlocal counter
        counter += 1
        actual_adapter = adapter or MockReadAdapter(
            {"record-1": {"id": "record-1", "secret": "CANARY-SECRET"}}
        )
        ledger = EvidenceLedger(tmp_path / f"ledger-{counter}.jsonl")
        runtime = SafetyRuntime(
            verifier=verifier or ManifestVerifier({"test-key": private_key.public_key()}),
            policy=policy or DefaultDenyPolicy(),
            budgets=BudgetLedger(manifest.budgets),
            kill_switch=kill_switch or KillSwitch(),
            credential_broker=InMemoryCredentialBroker({"fixture-credential": "CREDENTIAL-SECRET"}),
            redactor=Redactor((*manifest.synthetic_secrets, "CREDENTIAL-SECRET")),
            adapter=actual_adapter,
            ledger=ledger,
            clock=lambda: FIXED_NOW,
        )
        return runtime, actual_adapter, ledger

    return factory
