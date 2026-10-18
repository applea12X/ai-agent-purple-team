"""Manifest 1.4, the attestation document, and the other Phase 4 contracts.

The load-bearing assertion is byte-identity: a 1.3 manifest built exactly as Phase 3 built it
must produce the same canonical bytes and digest after the 1.4 fields exist, or every recorded
signature and seed hash in the project silently breaks.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from ipaddress import IPv4Address

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import ValidationError

from purpleloop.runtime.supportlab import supportlab_agent_manifest, supportlab_manifest
from purpleloop.schemas.action import SideEffectClass
from purpleloop.schemas.authorization import (
    AssetScope,
    AuthorizationManifest,
    BudgetLimits,
    Phase1Grants,
)
from purpleloop.schemas.phase2 import OwnershipScope, Phase2Grants
from purpleloop.schemas.phase3 import DecodingParameters, ModelPin, Phase3Grants
from purpleloop.schemas.phase4 import (
    AttestationMaterials,
    NightlyScope,
    Phase4Grants,
    RegressionEntry,
    RegressionRegistry,
    ReproductionRecord,
    RetentionRule,
    RunAttestation,
    SmokeSet,
    StochasticRunOutcome,
)

DIGEST = "a" * 64
EPOCH = datetime(2026, 1, 1, tzinfo=UTC)


def grants() -> Phase4Grants:
    return Phase4Grants(
        attestation_key_ids=frozenset({"ci-key"}),
        retention=(
            RetentionRule(artifact_kind="raw-ledgers", days=0, rationale="load-bearing"),
            RetentionRule(artifact_kind="model-transcripts", days=30, rationale="bulk"),
        ),
        nightly_scope=NightlyScope(
            scenario_ids=frozenset({"agent-direct-injection"}), repetitions=5
        ),
    )


def manifest_14(**overrides: object) -> AuthorizationManifest:
    now = datetime.now(UTC)
    fields: dict[str, object] = {
        "schema_version": "1.4.0",
        "engagement_id": "phase4-lane",
        "owner": "fixture-owner",
        "approvers": ("operator",),
        "key_id": "k",
        "issued_at": now - timedelta(seconds=1),
        "valid_from": now - timedelta(seconds=1),
        "valid_until": now + timedelta(hours=1),
        "phase1": Phase1Grants(defense_profiles=frozenset({"object-ownership"})),
        "phase2": Phase2Grants(
            ownership_seed=42,
            ownership=(OwnershipScope(tenant_id="org-a", resource_ids=frozenset({"ticket-a1"})),),
            database_credential_handle="supportlab-database",
            containment_prefix="purpleloop-agent",
        ),
        "phase3": Phase3Grants(
            model_credential_handle="model-api",
            model_pins=(
                ModelPin(
                    pin_id="offline",
                    provider="offline",
                    model_id="scripted",
                    decoding=DecodingParameters(seed=7),
                    system_prompt_hash=DIGEST,
                ),
            ),
            token_budget=1000,
            cost_microusd_budget=1000,
        ),
        "phase4": grants(),
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


def test_manifest_14_round_trips() -> None:
    manifest = manifest_14()
    reloaded = AuthorizationManifest.model_validate_json(manifest.model_dump_json())
    assert reloaded.canonical_bytes() == manifest.canonical_bytes()
    assert reloaded.phase4 is not None
    assert reloaded.phase4.retention_for("raw-ledgers") is not None
    assert reloaded.phase4.retention_for("bundles") is None


def test_phase4_grants_require_manifest_14() -> None:
    with pytest.raises(ValidationError, match="require manifest 1.4"):
        manifest_14(schema_version="1.3.0")


def test_manifest_14_requires_explicit_phase4_grants() -> None:
    with pytest.raises(ValidationError, match="explicit phase4 grants"):
        manifest_14(phase4=None)


def test_existing_manifests_keep_byte_identical_canonical_bytes() -> None:
    """The Phase 2 and Phase 3 builders' output is unchanged by the 1.4 additions."""
    key = Ed25519PrivateKey.generate()
    now = EPOCH
    for built in (
        supportlab_manifest(key, seed=42, now=now),
        supportlab_agent_manifest(key, seed=42, now=now),
    ):
        assert built.phase4 is None
        dumped = built.model_dump(mode="json", exclude_none=True)
        assert "phase4" not in dumped, "an absent grant must not serialize"
        reloaded = AuthorizationManifest.model_validate(dumped)
        assert reloaded.canonical_bytes() == built.canonical_bytes()
        assert reloaded.manifest_digest() == built.manifest_digest()


def test_retention_rules_are_unique_per_kind() -> None:
    with pytest.raises(ValidationError, match="one retention rule"):
        Phase4Grants(
            attestation_key_ids=frozenset({"k"}),
            retention=(
                RetentionRule(artifact_kind="bundles", days=1, rationale="a"),
                RetentionRule(artifact_kind="bundles", days=2, rationale="b"),
            ),
        )


def test_nightly_scope_holds_the_prd_repetition_floor() -> None:
    with pytest.raises(ValidationError):
        NightlyScope(scenario_ids=frozenset({"s"}), repetitions=4)


def attestation(**overrides: object) -> RunAttestation:
    fields: dict[str, object] = {
        "subject_digest": DIGEST,
        "subject_kind": "run-bundle",
        "builder": "test",
        "key_provenance": "provided",
        "created_at": EPOCH,
        "materials": AttestationMaterials(manifest_digest=DIGEST),
        "key_id": "k",
        "signature": "",
    }
    fields.update(overrides)
    return RunAttestation.model_validate(fields)


def test_attestation_signed_bytes_exclude_the_signature() -> None:
    unsigned = attestation()
    signed = attestation(signature="c2ln")
    assert unsigned.signed_bytes() == signed.signed_bytes()
    assert unsigned.attestation_digest() == signed.attestation_digest()


def test_attestation_rejects_a_malformed_subject() -> None:
    with pytest.raises(ValidationError):
        attestation(subject_digest="not-a-digest")
    with pytest.raises(ValidationError):
        attestation(materials=AttestationMaterials(scenario_digests=("junk",)))


def test_stochastic_outcomes_are_a_closed_vocabulary() -> None:
    outcome = StochasticRunOutcome(
        outcome="endpoint-error", reason_code="MODEL_PROVIDER_UNAVAILABLE"
    )
    assert outcome.outcome == "endpoint-error"
    with pytest.raises(ValidationError):
        StochasticRunOutcome(outcome="flaky", reason_code="X")  # type: ignore[arg-type]


def test_reproduction_record_requires_a_gap_reason_below_one() -> None:
    with pytest.raises(ValidationError, match="gap reason"):
        ReproductionRecord(
            scenario_id="s", n=5, matching=4, rate=0.8, seed_policy="fixed-per-repetition"
        )
    ok = ReproductionRecord(
        scenario_id="s",
        n=5,
        matching=4,
        rate=0.8,
        mismatched_repetitions=(3,),
        seed_policy="fixed-per-repetition",
        gap_reason="provider variance",
    )
    assert ok.rate == 0.8


def test_regression_entry_status_rules() -> None:
    with pytest.raises(ValidationError, match="pytest node id"):
        RegressionEntry(finding_class="f", scenario_id="s", status="covered", test="not-a-node-id")
    with pytest.raises(ValidationError, match="record why"):
        RegressionEntry(finding_class="f", scenario_id="s", status="uncovered")
    retired = RegressionEntry(
        finding_class="f", scenario_id="s", status="retired", reason="scenario replaced"
    )
    registry = RegressionRegistry(
        entries=(
            retired,
            RegressionEntry(
                finding_class="g", scenario_id="s2", status="covered", test="tests/x.py::test_y"
            ),
        )
    )
    assert registry.coverage == 1.0  # retired entries are excluded with their reason


def test_registry_coverage_counts_uncovered_entries() -> None:
    registry = RegressionRegistry(
        entries=(
            RegressionEntry(
                finding_class="a", scenario_id="s1", status="covered", test="tests/x.py::test_a"
            ),
            RegressionEntry(
                finding_class="b", scenario_id="s2", status="uncovered", reason="not yet pinned"
            ),
        )
    )
    assert registry.coverage == 0.5


def test_smoke_set_must_cover_every_lane() -> None:
    members = [{"lane": "agent", "scenario_id": f"agent-{i}"} for i in range(12)]
    with pytest.raises(ValidationError, match="every lane"):
        SmokeSet.model_validate(
            {"schema_version": "1.4.0", "wall_time_target_seconds": 600, "scenarios": members}
        )
