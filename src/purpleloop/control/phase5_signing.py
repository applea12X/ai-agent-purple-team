"""Signing and verification for Phase 5's human-signed documents.

Risk approvals, evaluation-matrix specs, and adjudication records are signed with exactly the
construction the authorization manifest (ADR 0002) and the run attestation (ADR 0012) already
use: Ed25519 over the RFC 8785 (JCS) canonical bytes of the document without its ``signature``
field, base64-encoded. No new cryptographic construction is introduced here; the only new code
is the per-document binding checks a signature alone cannot express.

Each verifier checks in a fixed order and raises :class:`SignedDocumentError` with a reason code
on the first failure: trusted key, then signature, then time window, then bindings. A document
that fails any check is refused whole -- there is no partially valid approval.

``require_key_separation`` is the pure key-separation rule (plan §2.2): the approver key may not
be a key that signs or attests under the manifest the approval covers. WP5.1's admission check
calls it; :func:`verify_risk_approval` calls it too, so a verified approval has already passed it.
"""

from __future__ import annotations

import base64
from collections.abc import Mapping
from datetime import UTC, datetime

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from purpleloop.schemas.authorization import AuthorizationManifest
from purpleloop.schemas.phase5 import (
    AdjudicationRecord,
    EvaluationMatrix,
    RiskApproval,
    ShadowReport,
    SignedRecord,
)


class SignedDocumentError(ValueError):
    """A Phase 5 signed document failed verification. ``reason_code`` names the first failure."""

    def __init__(self, reason_code: str, message: str) -> None:
        self.reason_code = reason_code
        super().__init__(message)


def sign_record[SignedT: SignedRecord](record: SignedT, private_key: Ed25519PrivateKey) -> SignedT:
    """Return ``record`` with its signature set -- the ``sign_manifest`` construction."""
    signature = base64.b64encode(private_key.sign(record.signed_bytes())).decode("ascii")
    return record.model_copy(update={"signature": signature})


def verify_record_signature(
    record: SignedRecord, public_keys: Mapping[str, Ed25519PublicKey]
) -> None:
    """Check the record is signed by the trusted key it names. Raises on any failure."""
    key = public_keys.get(record.signing_key_id)
    if key is None:
        raise SignedDocumentError("UNKNOWN_SIGNING_KEY", "record signing key is not trusted")
    try:
        key.verify(base64.b64decode(record.signature, validate=True), record.signed_bytes())
    except (InvalidSignature, ValueError) as exc:
        raise SignedDocumentError("INVALID_SIGNATURE", "record signature is invalid") from exc


def key_separation_violations(
    approver_key_id: str, manifest: AuthorizationManifest
) -> tuple[str, ...]:
    """Every role the approver key also holds under ``manifest``; empty when separated.

    The roles checked are the manifest signing key and each attestation key (manifest 1.4+).
    Separation is by key id. It is a structural control, not a claim about people: two key ids
    held by one author are still one author, and acceptance notes must say so.
    """
    violations: list[str] = []
    if approver_key_id == manifest.key_id:
        violations.append("manifest-signing-key")
    if manifest.phase4 is not None and approver_key_id in manifest.phase4.attestation_key_ids:
        violations.append("attestation-key")
    return tuple(violations)


def require_key_separation(approver_key_id: str, manifest: AuthorizationManifest) -> None:
    """Refuse an approver key that may also sign or attest under the manifest."""
    violations = key_separation_violations(approver_key_id, manifest)
    if violations:
        raise SignedDocumentError(
            "APPROVER_KEY_NOT_SEPARATE",
            "the approver key also holds: " + ", ".join(violations),
        )


def verify_risk_approval(
    approval: RiskApproval,
    public_keys: Mapping[str, Ed25519PublicKey],
    *,
    manifest: AuthorizationManifest,
    shadow_report: ShadowReport | None = None,
    now: datetime | None = None,
) -> RiskApproval:
    """Verify an approval against the manifest it claims to cover.

    Checks: trusted approver key; signature; ``issued_at <= now < expires_at``; the manifest's
    engagement and capability surface; key separation; and, when the report is supplied, that
    ``shadow_report`` is the exact report the approval names, for the same engagement. Whether
    the approval's delta equals the manifest's computed delta is :meth:`RiskApproval.covers`,
    called by WP5.1 with ``capability_delta``'s output.
    """
    current = (now or datetime.now(UTC)).astimezone(UTC)
    verify_record_signature(approval, public_keys)
    if current < approval.issued_at:
        raise SignedDocumentError("APPROVAL_NOT_YET_VALID", "approval is not yet valid")
    if current >= approval.expires_at:
        raise SignedDocumentError("APPROVAL_EXPIRED", "approval has expired")
    if approval.engagement_id != manifest.engagement_id:
        raise SignedDocumentError(
            "APPROVAL_ENGAGEMENT_MISMATCH", "approval was granted for a different engagement"
        )
    if approval.manifest_surface_digest != manifest.capability_surface_digest():
        raise SignedDocumentError(
            "APPROVAL_MANIFEST_MISMATCH", "approval covers a different capability surface"
        )
    require_key_separation(approval.approver_key_id, manifest)
    if shadow_report is not None:
        if shadow_report.report_digest() != approval.shadow_report_digest:
            raise SignedDocumentError(
                "APPROVAL_SHADOW_MISMATCH", "approval names a different shadow report"
            )
        if shadow_report.engagement_id != approval.engagement_id:
            raise SignedDocumentError(
                "APPROVAL_SHADOW_MISMATCH", "shadow report belongs to a different engagement"
            )
    return approval


def verify_matrix_spec(
    spec: EvaluationMatrix,
    public_keys: Mapping[str, Ed25519PublicKey],
    *,
    manifest: AuthorizationManifest | None = None,
) -> EvaluationMatrix:
    """Verify a matrix spec; with a manifest, also that it is the one authorized for spend."""
    verify_record_signature(spec, public_keys)
    if manifest is not None:
        if spec.engagement_id != manifest.engagement_id:
            raise SignedDocumentError(
                "MATRIX_ENGAGEMENT_MISMATCH", "matrix spec belongs to a different engagement"
            )
        scope = manifest.phase5.matrix_scope if manifest.phase5 is not None else None
        if scope != spec.matrix_digest():
            raise SignedDocumentError(
                "MATRIX_NOT_AUTHORIZED", "the manifest does not authorize this matrix spec"
            )
    return spec


def verify_adjudication(
    record: AdjudicationRecord,
    public_keys: Mapping[str, Ed25519PublicKey],
    *,
    bundle_digest: str | None = None,
) -> AdjudicationRecord:
    """Verify an adjudication record; with a digest, also that it labels that bundle."""
    verify_record_signature(record, public_keys)
    if bundle_digest is not None and record.bundle_digest != bundle_digest:
        raise SignedDocumentError(
            "ADJUDICATION_BUNDLE_MISMATCH", "record labels a finding in a different bundle"
        )
    return record
