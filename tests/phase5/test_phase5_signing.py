"""Risk approvals, adjudication records, and matrix specs: signing, verification, tampering.

Every tamper case asserts the specific reason code, so a verifier that refuses for the wrong
reason -- or accepts and happens to fail later -- does not pass.
"""

from __future__ import annotations

import base64
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
import rfc8785
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import ValidationError

from purpleloop.control.manifest import sign_manifest
from purpleloop.control.phase5_signing import (
    SignedDocumentError,
    key_separation_violations,
    require_key_separation,
    sign_record,
    verify_adjudication,
    verify_matrix_spec,
    verify_record_signature,
    verify_risk_approval,
)
from purpleloop.reporting.phase5_references import reference_adjudication, reference_matrix
from purpleloop.schemas.authorization import AuthorizationManifest
from purpleloop.schemas.phase4 import Phase4Grants, RetentionRule
from purpleloop.schemas.phase5 import (
    ActionClass,
    AdjudicationRecord,
    CapabilityIncrease,
    Phase5Grants,
    RiskApproval,
    ShadowReport,
)

APPROVER = "approver-key"
DELTA = frozenset({CapabilityIncrease.NEW_ACTION_CLASS, CapabilityIncrease.NEW_TARGET_FIXTURE})

MakeManifest = Callable[..., AuthorizationManifest]
MakeReport = Callable[..., ShadowReport]


def unsigned_approval(
    manifest: AuthorizationManifest, report: ShadowReport, now: datetime, **overrides: Any
) -> RiskApproval:
    fields: dict[str, Any] = {
        "approval_id": "approval-code-exec",
        "engagement_id": manifest.engagement_id,
        "baseline_digest": "e" * 64,
        "manifest_surface_digest": manifest.capability_surface_digest(),
        "capability_delta": DELTA,
        "shadow_report_digest": report.report_digest(),
        "approver": "the author, holding a separate offline key",
        "approver_key_id": APPROVER,
        "issued_at": now - timedelta(minutes=10),
        "expires_at": now + timedelta(days=7),
        "rationale": "code-exec reached only inside the sandbox in shadow",
        "signature": "",
    }
    fields.update(overrides)
    return RiskApproval.model_validate(fields)


@pytest.fixture
def setting(
    make_manifest: MakeManifest,
    make_shadow_report: MakeReport,
    approver_key: Ed25519PrivateKey,
    now: datetime,
) -> tuple[AuthorizationManifest, ShadowReport, RiskApproval]:
    manifest = make_manifest(
        phase5=Phase5Grants(
            action_classes=frozenset({ActionClass.READ, ActionClass.CODE_EXEC}),
            risk_approvals=frozenset({"f" * 64}),
        )
    )
    report = make_shadow_report()
    approval = sign_record(unsigned_approval(manifest, report, now), approver_key)
    return manifest, report, approval


def keys(approver_key: Ed25519PrivateKey) -> dict[str, Any]:
    return {APPROVER: approver_key.public_key()}


def reason(excinfo: pytest.ExceptionInfo[SignedDocumentError]) -> str:
    return excinfo.value.reason_code


def test_a_signed_approval_verifies_against_its_manifest_and_report(
    setting: tuple[AuthorizationManifest, ShadowReport, RiskApproval],
    approver_key: Ed25519PrivateKey,
    now: datetime,
) -> None:
    manifest, report, approval = setting
    verified = verify_risk_approval(
        approval, keys(approver_key), manifest=manifest, shadow_report=report, now=now
    )
    assert verified == approval
    assert approval.covers(DELTA)
    assert not approval.covers(DELTA | {CapabilityIncrease.WIDENED_EGRESS})
    assert not approval.covers(frozenset({CapabilityIncrease.NEW_ACTION_CLASS}))


def test_the_signature_is_the_manifest_construction(
    setting: tuple[AuthorizationManifest, ShadowReport, RiskApproval],
    approver_key: Ed25519PrivateKey,
) -> None:
    """Ed25519 over JCS bytes without the signature field -- ADR 0002, no new construction."""
    _, _, approval = setting
    payload = approval.model_dump(mode="json", exclude_none=True, exclude={"signature"})
    # JCS over the JSON payload, with the set-derived delta sorted the way ``order_sets`` does.
    payload["capability_delta"] = sorted(payload["capability_delta"], key=rfc8785.dumps)
    assert rfc8785.dumps(payload) == approval.signed_bytes()
    approver_key.public_key().verify(base64.b64decode(approval.signature), rfc8785.dumps(payload))
    # And the same key signs a manifest's bytes the same way.
    manifest = setting[0]
    signed_manifest = sign_manifest(manifest, approver_key)
    approver_key.public_key().verify(
        base64.b64decode(signed_manifest.signature), manifest.signed_bytes()
    )


def test_signed_bytes_exclude_the_signature(
    setting: tuple[AuthorizationManifest, ShadowReport, RiskApproval],
) -> None:
    _, _, approval = setting
    blank = approval.model_copy(update={"signature": ""})
    assert blank.signed_bytes() == approval.signed_bytes()
    assert blank.approval_digest() == approval.approval_digest()


@pytest.mark.parametrize(
    "update",
    [
        {"capability_delta": frozenset({CapabilityIncrease.NEW_ACTION_CLASS})},
        {"shadow_report_digest": "0" * 64},
        {"expires_at": datetime(2027, 1, 1, tzinfo=UTC)},
        {"rationale": "flipped after signing"},
        {"engagement_id": "phase5-lane-2"},
    ],
)
def test_a_statement_flip_after_signing_is_refused(
    setting: tuple[AuthorizationManifest, ShadowReport, RiskApproval],
    approver_key: Ed25519PrivateKey,
    now: datetime,
    update: dict[str, Any],
) -> None:
    manifest, report, approval = setting
    tampered = approval.model_copy(update=update)
    assert tampered.signed_bytes() != approval.signed_bytes()
    with pytest.raises(SignedDocumentError) as excinfo:
        verify_risk_approval(
            tampered, keys(approver_key), manifest=manifest, shadow_report=report, now=now
        )
    assert reason(excinfo) == "INVALID_SIGNATURE"


def test_a_different_key_under_the_trusted_id_is_refused(
    setting: tuple[AuthorizationManifest, ShadowReport, RiskApproval], now: datetime
) -> None:
    manifest, report, approval = setting
    impostor = {APPROVER: Ed25519PrivateKey.generate().public_key()}
    with pytest.raises(SignedDocumentError) as excinfo:
        verify_risk_approval(approval, impostor, manifest=manifest, shadow_report=report, now=now)
    assert reason(excinfo) == "INVALID_SIGNATURE"


def test_an_untrusted_key_id_is_refused(
    setting: tuple[AuthorizationManifest, ShadowReport, RiskApproval],
    approver_key: Ed25519PrivateKey,
    now: datetime,
) -> None:
    manifest, _, approval = setting
    with pytest.raises(SignedDocumentError) as excinfo:
        verify_risk_approval(
            approval, {"someone-else": approver_key.public_key()}, manifest=manifest, now=now
        )
    assert reason(excinfo) == "UNKNOWN_SIGNING_KEY"


def test_a_malformed_signature_is_refused(
    setting: tuple[AuthorizationManifest, ShadowReport, RiskApproval],
    approver_key: Ed25519PrivateKey,
    now: datetime,
) -> None:
    manifest, _, approval = setting
    for garbage in ("", "not base64!", base64.b64encode(b"short").decode()):
        with pytest.raises(SignedDocumentError) as excinfo:
            verify_risk_approval(
                approval.model_copy(update={"signature": garbage}),
                keys(approver_key),
                manifest=manifest,
                now=now,
            )
        assert reason(excinfo) == "INVALID_SIGNATURE"


def test_an_expired_or_premature_approval_is_refused(
    setting: tuple[AuthorizationManifest, ShadowReport, RiskApproval],
    approver_key: Ed25519PrivateKey,
) -> None:
    manifest, _, approval = setting
    with pytest.raises(SignedDocumentError) as excinfo:
        verify_risk_approval(
            approval, keys(approver_key), manifest=manifest, now=approval.expires_at
        )
    assert reason(excinfo) == "APPROVAL_EXPIRED"
    with pytest.raises(SignedDocumentError) as excinfo:
        verify_risk_approval(
            approval,
            keys(approver_key),
            manifest=manifest,
            now=approval.issued_at - timedelta(seconds=1),
        )
    assert reason(excinfo) == "APPROVAL_NOT_YET_VALID"


def test_an_approver_key_that_is_an_attestation_key_is_refused(
    make_manifest: MakeManifest,
    make_shadow_report: MakeReport,
    approver_key: Ed25519PrivateKey,
    now: datetime,
) -> None:
    manifest = make_manifest(
        phase4=Phase4Grants(
            attestation_key_ids=frozenset({"ci-key", APPROVER}),
            retention=(RetentionRule(artifact_kind="raw-ledgers", days=0, rationale="kept"),),
        )
    )
    report = make_shadow_report()
    approval = sign_record(unsigned_approval(manifest, report, now), approver_key)
    assert key_separation_violations(APPROVER, manifest) == ("attestation-key",)
    with pytest.raises(SignedDocumentError) as excinfo:
        verify_risk_approval(approval, keys(approver_key), manifest=manifest, now=now)
    assert reason(excinfo) == "APPROVER_KEY_NOT_SEPARATE"


def test_an_approver_key_that_signs_the_manifest_is_refused(make_manifest: MakeManifest) -> None:
    manifest = make_manifest(key_id=APPROVER)
    assert key_separation_violations(APPROVER, manifest) == ("manifest-signing-key",)
    with pytest.raises(SignedDocumentError) as excinfo:
        require_key_separation(APPROVER, manifest)
    assert reason(excinfo) == "APPROVER_KEY_NOT_SEPARATE"
    # Separated keys pass, and the check is pure: same inputs, same answer, nothing mutated.
    other = make_manifest()
    before = other.canonical_bytes()
    assert key_separation_violations(APPROVER, other) == ()
    require_key_separation(APPROVER, other)
    assert other.canonical_bytes() == before


def test_an_approval_is_bound_to_its_engagement_manifest_and_report(
    setting: tuple[AuthorizationManifest, ShadowReport, RiskApproval],
    make_manifest: MakeManifest,
    make_shadow_report: MakeReport,
    approver_key: Ed25519PrivateKey,
    now: datetime,
) -> None:
    manifest, report, approval = setting
    trusted = keys(approver_key)
    with pytest.raises(SignedDocumentError) as excinfo:
        verify_risk_approval(
            approval, trusted, manifest=make_manifest(engagement_id="another-engagement"), now=now
        )
    assert reason(excinfo) == "APPROVAL_ENGAGEMENT_MISMATCH"
    widened = make_manifest(
        phase5=Phase5Grants(
            action_classes=frozenset(
                {ActionClass.READ, ActionClass.CODE_EXEC, ActionClass.EXTERNAL_SEND}
            ),
            risk_approvals=frozenset({"f" * 64}),
        )
    )
    with pytest.raises(SignedDocumentError) as excinfo:
        verify_risk_approval(approval, trusted, manifest=widened, now=now)
    assert reason(excinfo) == "APPROVAL_MANIFEST_MISMATCH"
    with pytest.raises(SignedDocumentError) as excinfo:
        verify_risk_approval(
            approval,
            trusted,
            manifest=manifest,
            shadow_report=make_shadow_report(unreachable_steps=0),
            now=now,
        )
    assert reason(excinfo) == "APPROVAL_SHADOW_MISMATCH"
    foreign = make_shadow_report(engagement_id="another-engagement")
    rebound = sign_record(
        approval.model_copy(update={"shadow_report_digest": foreign.report_digest()}),
        approver_key,
    )
    with pytest.raises(SignedDocumentError) as excinfo:
        verify_risk_approval(rebound, trusted, manifest=manifest, shadow_report=foreign, now=now)
    assert reason(excinfo) == "APPROVAL_SHADOW_MISMATCH"
    # The approval still verifies after the manifest names it: the surface digest excludes it.
    named = make_manifest(
        phase5=Phase5Grants(
            action_classes=frozenset({ActionClass.READ, ActionClass.CODE_EXEC}),
            risk_approvals=frozenset({approval.approval_digest()}),
        )
    )
    assert verify_risk_approval(approval, trusted, manifest=named, shadow_report=report, now=now)


def test_an_approval_must_name_a_delta_and_a_forward_window(
    setting: tuple[AuthorizationManifest, ShadowReport, RiskApproval], now: datetime
) -> None:
    manifest, report, _ = setting
    with pytest.raises(ValidationError):
        unsigned_approval(manifest, report, now, capability_delta=frozenset())
    with pytest.raises(ValidationError, match="expire after"):
        unsigned_approval(manifest, report, now, expires_at=now - timedelta(minutes=10))
    with pytest.raises(ValidationError):
        unsigned_approval(manifest, report, now, capability_delta=frozenset({"bigger-model"}))


# --- adjudication -----------------------------------------------------------------------------


def test_an_adjudication_record_signs_verifies_and_detects_a_label_flip() -> None:
    key = Ed25519PrivateKey.generate()
    trusted = {"reference-reviewer-key": key.public_key()}
    record = sign_record(reference_adjudication(), key)
    assert verify_adjudication(record, trusted, bundle_digest="0" * 64) == record
    flipped = record.model_copy(update={"label": "false-positive"})
    with pytest.raises(SignedDocumentError) as excinfo:
        verify_adjudication(flipped, trusted)
    assert reason(excinfo) == "INVALID_SIGNATURE"
    unblinded = record.model_copy(update={"blinded": False})
    with pytest.raises(SignedDocumentError) as excinfo:
        verify_adjudication(unblinded, trusted)
    assert reason(excinfo) == "INVALID_SIGNATURE"
    with pytest.raises(SignedDocumentError) as excinfo:
        verify_adjudication(record, trusted, bundle_digest="1" * 64)
    assert reason(excinfo) == "ADJUDICATION_BUNDLE_MISMATCH"
    impostor = {"reference-reviewer-key": Ed25519PrivateKey.generate().public_key()}
    with pytest.raises(SignedDocumentError) as excinfo:
        verify_adjudication(record, impostor)
    assert reason(excinfo) == "INVALID_SIGNATURE"


def test_an_adjudication_round_trips_and_validates() -> None:
    record = reference_adjudication()
    assert AdjudicationRecord.model_validate_json(record.model_dump_json()) == record
    base = record.model_dump(mode="python")
    with pytest.raises(ValidationError, match="must cite the evidence"):
        AdjudicationRecord.model_validate({**base, "cited_evidence_ids": ()})
    assert AdjudicationRecord.model_validate(
        {**base, "label": "cannot-tell", "cited_evidence_ids": ()}
    )
    with pytest.raises(ValidationError):
        AdjudicationRecord.model_validate({**base, "label": "probably"})
    with pytest.raises(ValidationError):
        AdjudicationRecord.model_validate({**base, "rationale": ""})
    with pytest.raises(ValidationError):
        AdjudicationRecord.model_validate({**base, "bundle_digest": "nope"})


# --- matrix spec ------------------------------------------------------------------------------


def test_a_matrix_spec_signs_and_is_bound_to_the_manifest_scope(
    make_manifest: MakeManifest,
) -> None:
    key = Ed25519PrivateKey.generate()
    trusted = {"reference-key": key.public_key()}
    spec = sign_record(reference_matrix(), key)
    verify_record_signature(spec, trusted)
    authorized = make_manifest(
        engagement_id="schema-reference",
        phase5=Phase5Grants(
            action_classes=frozenset({ActionClass.READ}), matrix_scope=spec.matrix_digest()
        ),
    )
    assert verify_matrix_spec(spec, trusted, manifest=authorized) == spec
    with pytest.raises(SignedDocumentError) as excinfo:
        verify_matrix_spec(spec, trusted, manifest=make_manifest(engagement_id="schema-reference"))
    assert reason(excinfo) == "MATRIX_NOT_AUTHORIZED"
    with pytest.raises(SignedDocumentError) as excinfo:
        verify_matrix_spec(spec, trusted, manifest=make_manifest())
    assert reason(excinfo) == "MATRIX_ENGAGEMENT_MISMATCH"
    raised = spec.model_copy(update={"cost_cap_microusd": 10_000_000})
    with pytest.raises(SignedDocumentError) as excinfo:
        verify_matrix_spec(raised, trusted)
    assert reason(excinfo) == "INVALID_SIGNATURE"
