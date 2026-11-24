"""Manifest 1.5: the Phase 5 grants, and byte-identity of every earlier manifest version.

The load-bearing assertion is byte-identity. The pinned digests below were computed at the phase
base (``a79f185``) *before* any Phase 5 code existed, by building each manifest exactly as the
earlier phases' builders do at a fixed instant. If the 1.5 additions moved any of them, every
recorded signature, manifest digest, and seed hash in the project would silently break.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from ipaddress import IPv4Address

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import ValidationError

from purpleloop.reporting.gates import _reference_manifest
from purpleloop.runtime.demo import demo_manifest
from purpleloop.runtime.supportlab import supportlab_agent_manifest, supportlab_manifest
from purpleloop.schemas.action import SideEffectClass
from purpleloop.schemas.authorization import AssetScope, AuthorizationManifest, BudgetLimits
from purpleloop.schemas.phase5 import (
    ACTION_CLASS_ORDER,
    CAPABILITY_INCREASES,
    ActionClass,
    CapabilityIncrease,
    Phase5Grants,
    highest_action_class,
)

EPOCH = datetime(2026, 1, 1, tzinfo=UTC)

#: Recorded at a79f185 with the pre-Phase-5 code; see the module docstring.
PINNED_MANIFEST_DIGESTS = {
    "1.0.0": "1c710b81d168f936d2eb5654424c0d7f8ac4bbbf4480da25207a019f2394b555",
    "1.1.0": "663c1dcbcce3cff2f7163443ccc4b33d2fc3621106503f6daa0157eca02966dc",
    "1.2.0": "7852c559e7a93755256f87886978b876179454575221ce80e67ebf2f562d8150",
    "1.3.0": "3186a47fedad754737761d8a465c2eeabe95b63d42774a258410eac7b5e1ef60",
    "1.3.0-reference": "e7d5ab431990e04600edd2c3a13eb5038985ebcc105e3a230adcc8362683c20e",
    "1.4.0-reference": "f9cb2c3562bff0185a3eea60c16dae6076413b58eedd3c1f555a7022c275f2c5",
}

Make = Callable[..., AuthorizationManifest]


def _phase0_manifest() -> AuthorizationManifest:
    return AuthorizationManifest(
        engagement_id="phase0-reference",
        owner="reference-owner",
        approvers=("reference-approver",),
        key_id="reference-key",
        issued_at=EPOCH,
        valid_from=EPOCH,
        valid_until=datetime(2026, 1, 2, tzinfo=UTC),
        assets=(
            AssetScope(
                asset_id="reference-asset",
                scheme="https",
                host="target.example",
                port=443,
                tenant_ids=frozenset({"tenant-a"}),
                allowed_resolved_addresses=frozenset({IPv4Address("192.0.2.10")}),
            ),
        ),
        allowed_adapters=frozenset({"mock-read"}),
        allowed_operations=frozenset({"record.read"}),
        budgets=BudgetLimits(requests=1, records=1),
        signature="",
    )


def test_existing_manifests_keep_byte_identical_canonical_bytes() -> None:
    """1.0-1.4 manifests: digests pinned at the phase base, and an absent grant never serializes."""
    key = Ed25519PrivateKey.generate()
    built = {
        "1.0.0": _phase0_manifest(),
        "1.1.0": demo_manifest(key, now=EPOCH),
        "1.2.0": supportlab_manifest(key, seed=42, now=EPOCH),
        "1.3.0": supportlab_agent_manifest(key, seed=42, now=EPOCH),
        "1.3.0-reference": _reference_manifest("1.3.0"),
        "1.4.0-reference": _reference_manifest("1.4.0"),
    }
    for name, manifest in built.items():
        assert manifest.phase5 is None
        assert manifest.manifest_digest() == PINNED_MANIFEST_DIGESTS[name], name
        dumped = manifest.model_dump(mode="json", exclude_none=True)
        assert "phase5" not in dumped, "an absent grant must not serialize"
        reloaded = AuthorizationManifest.model_validate(dumped)
        assert reloaded.canonical_bytes() == manifest.canonical_bytes()
        assert reloaded.manifest_digest() == manifest.manifest_digest()
        # Without Phase 5 grants the approval-free surface is the manifest itself.
        assert manifest.capability_surface_digest() == manifest.manifest_digest()


def test_manifest_15_round_trips(make_manifest: Make) -> None:
    manifest = make_manifest(
        phase5=Phase5Grants(
            action_classes=frozenset({ActionClass.READ, ActionClass.CODE_EXEC}),
            risk_approvals=frozenset({"b" * 64, "c" * 64}),
            run_mode="shadow",
            matrix_scope="d" * 64,
            telemetry="otel-collector",
        )
    )
    reloaded = AuthorizationManifest.model_validate_json(manifest.model_dump_json())
    assert reloaded == manifest
    assert reloaded.canonical_bytes() == manifest.canonical_bytes()
    assert reloaded.phase5 is not None and reloaded.phase5.run_mode == "shadow"


def test_manifest_15_canonical_bytes_do_not_depend_on_set_order(make_manifest: Make) -> None:
    forward = make_manifest(
        phase5=Phase5Grants(
            action_classes=frozenset([ActionClass.READ, ActionClass.WRITE, ActionClass.CODE_EXEC]),
            risk_approvals=frozenset(["b" * 64, "c" * 64]),
        ),
        allowed_side_effects=frozenset({SideEffectClass.READ, SideEffectClass.WRITE}),
    )
    backward = make_manifest(
        phase5=Phase5Grants(
            action_classes=frozenset([ActionClass.CODE_EXEC, ActionClass.WRITE, ActionClass.READ]),
            risk_approvals=frozenset(["c" * 64, "b" * 64]),
        ),
        allowed_side_effects=frozenset({SideEffectClass.WRITE, SideEffectClass.READ}),
    )
    assert forward.canonical_bytes() == backward.canonical_bytes()


def test_run_mode_defaults_to_execute_and_telemetry_to_absent() -> None:
    grants = Phase5Grants(action_classes=frozenset({ActionClass.READ}))
    assert grants.run_mode == "execute"
    assert grants.telemetry is None and grants.matrix_scope is None
    assert grants.risk_approvals == frozenset()
    with pytest.raises(ValidationError):
        Phase5Grants(action_classes=frozenset({ActionClass.READ}), run_mode="dry")  # type: ignore[arg-type]


def test_phase5_grants_require_manifest_15(make_manifest: Make) -> None:
    with pytest.raises(ValidationError, match="require manifest 1.5"):
        make_manifest(schema_version="1.4.0")


def test_manifest_15_requires_explicit_phase5_grants(make_manifest: Make) -> None:
    with pytest.raises(ValidationError, match="explicit phase5 grants"):
        make_manifest(phase5=None)


def test_manifest_15_keeps_every_earlier_grant(make_manifest: Make) -> None:
    with pytest.raises(ValidationError, match="explicit phase4 grants"):
        make_manifest(phase4=None)
    with pytest.raises(ValidationError, match="explicit phase3 grants"):
        make_manifest(phase3=None)
    with pytest.raises(ValidationError, match="Phase 1 requires explicit grants"):
        make_manifest(phase1=None)


def test_manifest_15_keeps_loopback_assets(make_manifest: Make) -> None:
    with pytest.raises(ValidationError, match="loopback"):
        make_manifest(
            assets=(
                AssetScope(
                    asset_id="remote",
                    scheme="https",
                    host="target.example",
                    port=443,
                    tenant_ids=frozenset({"org-a"}),
                    allowed_resolved_addresses=frozenset({IPv4Address("192.0.2.10")}),
                ),
            )
        )


def test_action_classes_cannot_be_empty_or_unknown() -> None:
    with pytest.raises(ValidationError):
        Phase5Grants(action_classes=frozenset())
    with pytest.raises(ValidationError):
        Phase5Grants.model_validate({"action_classes": ["read", "delete-everything"]})


def test_a_permitted_side_effect_requires_its_action_class(make_manifest: Make) -> None:
    with pytest.raises(ValidationError, match="requires its action class"):
        make_manifest(allowed_side_effects=frozenset({SideEffectClass.READ, SideEffectClass.WRITE}))
    with pytest.raises(ValidationError, match="requires its action class"):
        make_manifest(phase5=Phase5Grants(action_classes=frozenset({ActionClass.CODE_EXEC})))


def test_telemetry_collector_must_be_a_signed_asset(make_manifest: Make) -> None:
    with pytest.raises(ValidationError, match="signed asset"):
        make_manifest(
            phase5=Phase5Grants(action_classes=frozenset({ActionClass.READ}), telemetry="elsewhere")
        )
    assert make_manifest(
        phase5=Phase5Grants(
            action_classes=frozenset({ActionClass.READ}), telemetry="otel-collector"
        )
    ).phase5


def test_approval_and_matrix_references_must_be_digests() -> None:
    with pytest.raises(ValidationError, match="SHA-256"):
        Phase5Grants(action_classes=frozenset({ActionClass.READ}), risk_approvals=frozenset({"x"}))
    with pytest.raises(ValidationError):
        Phase5Grants(action_classes=frozenset({ActionClass.READ}), matrix_scope="A" * 64)


def test_action_class_order_is_closed_and_total() -> None:
    assert [item.value for item in ACTION_CLASS_ORDER] == [
        "read",
        "write",
        "external-send",
        "code-exec",
    ]
    assert set(ACTION_CLASS_ORDER) == set(ActionClass)
    assert [item.rank for item in ACTION_CLASS_ORDER] == [0, 1, 2, 3]
    assert highest_action_class([ActionClass.WRITE, ActionClass.READ]) is ActionClass.WRITE
    assert highest_action_class([ActionClass.CODE_EXEC, ActionClass.WRITE]) is ActionClass.CODE_EXEC
    assert highest_action_class([]) is None


def test_capability_increase_vocabulary_is_exactly_the_plan_enum() -> None:
    assert {item.value for item in CAPABILITY_INCREASES} == {
        "new-action-class",
        "new-adapter-or-operation",
        "new-target-fixture",
        "widened-egress",
        "raised-attacker-caps",
        "proposal-source-change",
    }
    assert set(CAPABILITY_INCREASES) == set(CapabilityIncrease)


def test_capability_surface_digest_ignores_only_the_approval_list(make_manifest: Make) -> None:
    def with_approvals(*digests: str, **overrides: object) -> AuthorizationManifest:
        return make_manifest(
            phase5=Phase5Grants(
                action_classes=frozenset({ActionClass.READ}), risk_approvals=frozenset(digests)
            ),
            **overrides,
        )

    bare = with_approvals()
    approved = with_approvals("b" * 64)
    other = with_approvals("b" * 64, "c" * 64)
    assert approved.manifest_digest() != bare.manifest_digest()
    assert approved.capability_surface_digest() == bare.capability_surface_digest()
    assert other.capability_surface_digest() == bare.capability_surface_digest()
    assert bare.capability_surface_digest() == bare.manifest_digest()
    widened = with_approvals("b" * 64, allowed_operations=frozenset({"ticket.read", "x.y"}))
    assert widened.capability_surface_digest() != approved.capability_surface_digest()
