"""Manifest 1.3: additive grants, and the two-plane split enforced at the schema boundary."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from ipaddress import IPv4Address

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import ValidationError

from purpleloop.runtime.supportlab import supportlab_manifest
from purpleloop.schemas.action import SideEffectClass
from purpleloop.schemas.authorization import (
    AssetScope,
    AuthorizationManifest,
    BudgetLimits,
    Phase1Grants,
)
from purpleloop.schemas.phase2 import OwnershipScope, Phase2Grants
from purpleloop.schemas.phase3 import DecodingParameters, ModelPin, Phase3Grants

DIGEST = "b" * 64


def pin(pin_id: str = "primary", provider: str = "vllm") -> ModelPin:
    return ModelPin(
        pin_id=pin_id,
        provider=provider,  # type: ignore[arg-type]
        model_id="synthetic-model",
        model_version="2026-05-01",
        decoding=DecodingParameters(seed=7),
        system_prompt_hash=DIGEST,
    )


def base_manifest(**overrides: object) -> AuthorizationManifest:
    now = datetime.now(UTC)
    fields: dict[str, object] = {
        "schema_version": "1.3.0",
        "engagement_id": "agent-lane",
        "owner": "fixture-owner",
        "approvers": ("operator",),
        "key_id": "k",
        "issued_at": now - timedelta(seconds=1),
        "valid_from": now - timedelta(seconds=1),
        "valid_until": now + timedelta(hours=1),
        "phase1": Phase1Grants(defense_profiles=frozenset({"object-ownership"})),
        # Phase 3 builds on the supportlab fixture, so it keeps signed ownership rather than
        # replacing it: a 1.3 manifest carries Phase 2 grants too.
        "phase2": Phase2Grants(
            ownership_seed=42,
            ownership=(OwnershipScope(tenant_id="org-a", resource_ids=frozenset({"ticket-a1"})),),
            database_credential_handle="supportlab-database",
            containment_prefix="purpleloop-agent",
        ),
        "assets": (
            AssetScope(
                asset_id="supportlab-data",
                scheme="http",
                host="127.0.0.1",
                port=28080,
                tenant_ids=frozenset({"org-a"}),
                allowed_resolved_addresses=frozenset({IPv4Address("127.0.0.1")}),
            ),
        ),
        "allowed_adapters": frozenset({"http"}),
        "allowed_operations": frozenset({"ticket.read"}),
        "allowed_side_effects": frozenset({SideEffectClass.READ}),
        "credential_handles": frozenset({"customer"}),
        "credential_scopes": {"customer": frozenset({"ticket.read"})},
        "budgets": BudgetLimits(requests=10, records=10),
        "signature": "",
    }
    fields.update(overrides)
    return AuthorizationManifest.model_validate(fields)


def test_phase3_grants_require_manifest_13() -> None:
    grants = Phase3Grants(
        model_assets=frozenset({"https://models.invalid:443"}),
        model_credential_handle="model-api",
        model_pins=(pin(),),
        token_budget=10_000,
        cost_microusd_budget=5_000,
    )
    assert base_manifest(phase3=grants).phase3 is grants
    with pytest.raises(ValidationError):
        base_manifest(schema_version="1.2.0", phase3=grants)


def test_manifest_13_requires_explicit_phase3_grants() -> None:
    with pytest.raises(ValidationError):
        base_manifest(phase3=None)


def test_a_model_endpoint_can_never_be_a_target_asset_origin() -> None:
    """ADR 0008. The model plane and the target plane cannot be made to overlap."""
    with pytest.raises(ValidationError, match="never be a target asset origin"):
        base_manifest(
            phase3=Phase3Grants(
                model_assets=frozenset({"http://127.0.0.1:28080"}),
                model_credential_handle="model-api",
                model_pins=(pin(),),
                token_budget=1,
                cost_microusd_budget=1,
            )
        )


def test_target_assets_stay_loopback_under_13() -> None:
    """Adding a model plane does not buy the target plane an off-host asset."""
    with pytest.raises(ValidationError, match="loopback"):
        base_manifest(
            assets=(
                AssetScope(
                    asset_id="remote",
                    scheme="https",
                    host="example.invalid",
                    port=443,
                    tenant_ids=frozenset({"org-a"}),
                    allowed_resolved_addresses=frozenset({IPv4Address("93.184.216.34")}),
                ),
            ),
            phase3=Phase3Grants(
                model_assets=frozenset({"https://models.invalid:443"}),
                model_credential_handle="model-api",
                model_pins=(pin(),),
                token_budget=1,
                cost_microusd_budget=1,
            ),
        )


def test_model_credential_can_never_be_an_attack_credential() -> None:
    with pytest.raises(ValidationError, match="model credential"):
        base_manifest(
            phase3=Phase3Grants(
                model_assets=frozenset({"https://models.invalid:443"}),
                model_credential_handle="customer",
                model_pins=(pin(),),
                token_budget=1,
                cost_microusd_budget=1,
            )
        )


def test_offline_only_engagement_authorizes_no_endpoint() -> None:
    """The absence of a grant is the control: an offline run has nowhere to go."""
    offline = Phase3Grants(
        model_credential_handle="model-api",
        model_pins=(
            ModelPin(
                pin_id="offline",
                provider="offline",
                model_id="offline",
                system_prompt_hash=DIGEST,
            ),
        ),
        token_budget=0,
        cost_microusd_budget=0,
    )
    assert offline.model_assets == frozenset()
    with pytest.raises(ValidationError, match="requires a signed model endpoint"):
        Phase3Grants(
            model_credential_handle="model-api",
            model_pins=(pin(),),
            token_budget=1,
            cost_microusd_budget=1,
        )
    with pytest.raises(ValidationError, match="must not authorize a model endpoint"):
        Phase3Grants(
            model_assets=frozenset({"https://models.invalid:443"}),
            model_credential_handle="model-api",
            model_pins=(
                ModelPin(
                    pin_id="offline",
                    provider="offline",
                    model_id="offline",
                    system_prompt_hash=DIGEST,
                ),
            ),
            token_budget=0,
            cost_microusd_budget=0,
        )


def test_enabled_judge_requires_an_authorized_pin() -> None:
    with pytest.raises(ValidationError, match="pinned judge model"):
        Phase3Grants(
            model_assets=frozenset({"https://models.invalid:443"}),
            model_credential_handle="model-api",
            model_pins=(pin(),),
            token_budget=1,
            cost_microusd_budget=1,
            judge_enabled=True,
        )
    with pytest.raises(ValidationError, match="authorized pin"):
        Phase3Grants(
            model_assets=frozenset({"https://models.invalid:443"}),
            model_credential_handle="model-api",
            model_pins=(pin(),),
            token_budget=1,
            cost_microusd_budget=1,
            judge_enabled=True,
            judge_model_pin="not-a-pin",
        )


def test_phase2_manifests_keep_byte_identical_canonical_bytes() -> None:
    """The 1.3 field is absent from a 1.2 document, so its signature is unchanged."""
    key = Ed25519PrivateKey.generate()
    now = datetime.now(UTC)
    first = supportlab_manifest(key, seed=42, now=now)
    second = supportlab_manifest(key, seed=42, now=now)
    assert first.phase3 is None
    assert first.canonical_bytes() == second.canonical_bytes()
    assert b"phase3" not in first.canonical_bytes()
    assert first.manifest_digest() == second.manifest_digest()
