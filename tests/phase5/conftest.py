"""Shared builders for the Phase 5 contract tests.

``tests`` is not a package and earlier suites are not edited, so these are fixtures rather than
imports from the Phase 4 tests; the manifest construction mirrors
``tests/phase4/test_phase4_contracts.py::manifest_14``.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from ipaddress import IPv4Address
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from purpleloop.schemas.action import BudgetRequest, SideEffectClass
from purpleloop.schemas.authorization import (
    AssetScope,
    AuthorizationManifest,
    BudgetLimits,
    Phase1Grants,
)
from purpleloop.schemas.phase2 import OwnershipScope, Phase2Grants
from purpleloop.schemas.phase3 import DecodingParameters, ModelPin, Phase3Grants
from purpleloop.schemas.phase4 import Phase4Grants, RetentionRule
from purpleloop.schemas.phase5 import ActionClass, Phase5Grants, ShadowReport

DIGEST = "a" * 64
NOW = datetime(2026, 6, 1, 12, 0, tzinfo=UTC)


def _manifest_fields() -> dict[str, Any]:
    return {
        "schema_version": "1.5.0",
        "engagement_id": "phase5-lane",
        "owner": "fixture-owner",
        "approvers": ("operator",),
        "key_id": "manifest-key",
        "issued_at": NOW - timedelta(hours=1),
        "valid_from": NOW - timedelta(hours=1),
        "valid_until": NOW + timedelta(hours=1),
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
        "phase4": Phase4Grants(
            attestation_key_ids=frozenset({"ci-key"}),
            retention=(RetentionRule(artifact_kind="raw-ledgers", days=0, rationale="kept"),),
        ),
        "phase5": Phase5Grants(action_classes=frozenset({ActionClass.READ})),
        "assets": (
            AssetScope(
                asset_id="supportlab-data",
                scheme="http",
                host="127.0.0.1",
                port=28080,
                tenant_ids=frozenset({"org-a"}),
                allowed_resolved_addresses=frozenset({IPv4Address("127.0.0.1")}),
            ),
            AssetScope(
                asset_id="otel-collector",
                scheme="http",
                host="127.0.0.1",
                port=24318,
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


@pytest.fixture
def make_manifest() -> Callable[..., AuthorizationManifest]:
    """A manifest 1.5 builder; keyword overrides replace top-level fields."""

    def make(**overrides: Any) -> AuthorizationManifest:
        fields = _manifest_fields()
        fields.update(overrides)
        return AuthorizationManifest.model_validate(fields)

    return make


@pytest.fixture
def make_shadow_report() -> Callable[..., ShadowReport]:
    def make(**overrides: Any) -> ShadowReport:
        fields: dict[str, Any] = {
            "run_id": "shadow-run-1",
            "engagement_id": "phase5-lane",
            "manifest_digest": DIGEST,
            "action_classes_reached": frozenset({ActionClass.READ, ActionClass.CODE_EXEC}),
            "operations_proposed": {"snippet.run": 3, "ticket.read": 1},
            "denials_by_reason": {"OPERATION_NOT_ALLOWED": 2},
            "would_be_budget": BudgetRequest(requests=4, records=4),
            "proposals_total": 4,
            "proposals_rejected": 1,
            "proposal_rejection_rate": 0.25,
            "suppressed_executions": 2,
            "unreachable_steps": 1,
            "created_at": NOW - timedelta(minutes=30),
        }
        fields.update(overrides)
        return ShadowReport.model_validate(fields)

    return make


@pytest.fixture
def approver_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


@pytest.fixture
def now() -> datetime:
    """The instant every Phase 5 contract test treats as the present."""
    return NOW
