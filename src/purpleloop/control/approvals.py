"""Admission enforcement for capability increases (WP5.1, plan §2.2, ADR 0014).

The rule, in one sentence: a manifest 1.5 in ``execute`` mode is admitted only if its capability
delta against the signed approved baseline is empty, or is exactly covered by one valid,
unexpired, key-separated :class:`~purpleloop.schemas.phase5.RiskApproval` that names this
manifest's capability surface, this baseline, and a shadow report produced on this manifest's
shadow twin. Everything else is refused with a reason code.

What is *not* subject to it:

- **Manifests 1.0-1.4** are the v1 surface. They carry no Phase 5 grants, are admitted exactly as
  before, and this module records nothing for them -- their ledgers are byte-identical.
- **Shadow manifests** (``run_mode: shadow``) are admitted with their delta recorded and no
  approval required: nothing they authorize executes, and the shadow run is what produces the
  evidence an approval is granted on.

No model, attacker, or judge component can produce an approval or a baseline; the kernel only
verifies them. Signing lives in ``control.phase5_signing`` and is driven by a human through
``purpleloop approve``.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from purpleloop.control.capabilities import capability_delta
from purpleloop.control.manifest import ManifestError
from purpleloop.control.phase5_signing import (
    SignedDocumentError,
    require_key_separation,
    sign_record,
    verify_record_signature,
    verify_risk_approval,
)
from purpleloop.schemas.authorization import AuthorizationManifest
from purpleloop.schemas.capability import CapabilityBaseline, CapabilitySurface, KeyProvenance
from purpleloop.schemas.phase5 import CapabilityIncrease, RiskApproval, ShadowReport


class ApprovalRefused(ManifestError):
    """Admission refused a manifest's capability increase. ``reason_code`` names why.

    A :class:`ManifestError`, so the safety runtime's existing admission handler records it as an
    ``ADMISSION`` denial and the runner reports the reason code as the run's reason -- which is
    what puts the refusal into the audit export.
    """

    def __init__(
        self,
        reason_code: str,
        message: str,
        *,
        delta: frozenset[CapabilityIncrease] = frozenset(),
    ) -> None:
        self.delta = delta
        super().__init__(reason_code, message)


@dataclass(frozen=True)
class AdmissionDecision:
    """What admission decided about one manifest's capability increase."""

    admitted: bool
    reason_code: str
    delta: frozenset[CapabilityIncrease] = frozenset()
    approval_digest: str | None = None
    baseline_digest: str | None = None

    def evidence(self) -> dict[str, object]:
        """The admission event's data: the delta and which approval covered it, never keys."""
        return {
            "capability_delta": sorted(item.value for item in self.delta),
            "approval_digest": self.approval_digest,
            "baseline_digest": self.baseline_digest,
        }


def shadow_twin(manifest: AuthorizationManifest) -> AuthorizationManifest:
    """The manifest a shadow run of ``manifest`` is admitted under: same surface, ``shadow`` mode.

    Everything is identical -- validity window, keys, every grant -- except ``run_mode`` and an
    emptied approval list (a shadow run needs no approval, and the approval cannot exist yet).
    The returned manifest is unsigned; sign it with the manifest key before running it. Its
    digest is what a shadow report must name for an approval to be accepted for ``manifest``.
    """
    if manifest.phase5 is None:
        raise ValueError("only a manifest 1.5 has a shadow twin")
    grants = manifest.phase5.model_copy(
        update={"run_mode": "shadow", "risk_approvals": frozenset()}
    )
    data = manifest.model_dump(mode="python", exclude_none=True)
    data["phase5"] = grants.model_dump(mode="python", exclude_none=True)
    data["signature"] = ""
    return AuthorizationManifest.model_validate(data)


def shadow_twin_digest(manifest: AuthorizationManifest) -> str:
    return shadow_twin(manifest).manifest_digest()


def with_approvals(
    manifest: AuthorizationManifest, approvals: Iterable[RiskApproval]
) -> AuthorizationManifest:
    """``manifest`` naming ``approvals`` by digest, unsigned. Its capability surface is kept."""
    if manifest.phase5 is None:
        raise ValueError("only a manifest 1.5 names risk approvals")
    digests = frozenset(approval.approval_digest() for approval in approvals)
    data = manifest.model_dump(mode="python", exclude_none=True)
    data["phase5"] = manifest.phase5.model_copy(update={"risk_approvals": digests}).model_dump(
        mode="python", exclude_none=True
    )
    data["signature"] = ""
    return AuthorizationManifest.model_validate(data)


@dataclass(frozen=True)
class ApprovalAdmission:
    """The trusted inputs admission needs: the baseline, the keys, and the documents.

    ``approvals`` and ``shadow_reports`` are the documents available to this admission, looked
    up by their own digests -- a manifest names an approval by digest, and an approval names its
    shadow report by digest, so a document can never be substituted under another's name.
    """

    baseline: CapabilityBaseline
    baseline_keys: Mapping[str, Ed25519PublicKey]
    approver_keys: Mapping[str, Ed25519PublicKey] = field(default_factory=dict)
    approvals: Mapping[str, RiskApproval] = field(default_factory=dict)
    shadow_reports: Mapping[str, ShadowReport] = field(default_factory=dict)

    @classmethod
    def of(
        cls,
        baseline: CapabilityBaseline,
        baseline_keys: Mapping[str, Ed25519PublicKey],
        *,
        approver_keys: Mapping[str, Ed25519PublicKey] | None = None,
        approvals: Iterable[RiskApproval] = (),
        shadow_reports: Iterable[ShadowReport] = (),
    ) -> ApprovalAdmission:
        return cls(
            baseline=baseline,
            baseline_keys=dict(baseline_keys),
            approver_keys=dict(approver_keys or {}),
            approvals={approval.approval_digest(): approval for approval in approvals},
            shadow_reports={report.report_digest(): report for report in shadow_reports},
        )

    def decide(self, manifest: AuthorizationManifest, *, now: datetime) -> AdmissionDecision:
        """Admit or refuse ``manifest``'s capability increase. Never raises; see :meth:`admit`."""
        try:
            return self.admit(manifest, now=now)
        except ApprovalRefused as exc:
            return AdmissionDecision(admitted=False, reason_code=exc.reason_code, delta=exc.delta)

    def admit(self, manifest: AuthorizationManifest, *, now: datetime) -> AdmissionDecision:
        """Admit ``manifest`` or raise :class:`ApprovalRefused`. Checks run in a fixed order."""
        if manifest.phase5 is None:
            return AdmissionDecision(admitted=True, reason_code="PRE_PHASE5_SURFACE")
        baseline = self.baseline
        try:
            verify_record_signature(baseline, self.baseline_keys)
            require_key_separation(baseline.key_id, manifest)
        except SignedDocumentError as exc:
            raise ApprovalRefused(f"BASELINE_{exc.reason_code}", str(exc)) from exc
        baseline_digest = baseline.baseline_digest()
        delta = capability_delta(baseline.surface, manifest)

        def refuse(reason: str, message: str) -> ApprovalRefused:
            return ApprovalRefused(
                reason, f"{message}; delta={sorted(d.value for d in delta)}", delta=delta
            )

        if manifest.phase5.run_mode == "shadow":
            return AdmissionDecision(
                admitted=True,
                reason_code="SHADOW_ADMITTED",
                delta=delta,
                baseline_digest=baseline_digest,
            )
        listed = manifest.phase5.risk_approvals
        if not delta:
            if listed:
                # An approval is an exact grant of a non-empty delta; naming one for a manifest
                # with no increase means the manifest and the approval disagree about it.
                raise refuse("APPROVAL_DELTA_MISMATCH", "an approval is named for no increase")
            return AdmissionDecision(
                admitted=True, reason_code="NO_CAPABILITY_INCREASE", baseline_digest=baseline_digest
            )
        if not listed:
            raise refuse("CAPABILITY_INCREASE_UNAPPROVED", "the manifest names no risk approval")
        if len(listed) > 1:
            # One approval names one exact delta; combining several would let a delta be
            # assembled from grants that were each made for a different increase.
            raise refuse("APPROVAL_AMBIGUOUS", "exactly one approval must cover the delta")
        (digest,) = tuple(listed)
        approval = self.approvals.get(digest)
        if approval is None or approval.approval_digest() != digest:
            raise refuse("APPROVAL_NOT_FOUND", "the named approval is not available")
        report = self.shadow_reports.get(approval.shadow_report_digest)
        if report is None:
            raise refuse(
                "APPROVAL_SHADOW_REPORT_MISSING", "the approval's shadow report is not available"
            )
        try:
            verify_risk_approval(
                approval, self.approver_keys, manifest=manifest, shadow_report=report, now=now
            )
        except SignedDocumentError as exc:
            raise refuse(exc.reason_code, str(exc)) from exc
        if approval.approver_key_id == baseline.key_id:
            raise refuse("APPROVER_KEY_NOT_SEPARATE", "the approver key also signed the baseline")
        if approval.baseline_digest != baseline_digest:
            raise refuse(
                "APPROVAL_BASELINE_MISMATCH", "the approval was computed against another baseline"
            )
        if report.manifest_digest != shadow_twin_digest(manifest):
            raise refuse(
                "APPROVAL_SHADOW_NOT_THIS_SURFACE",
                "the shadow report was not produced on this manifest's shadow twin",
            )
        if not approval.covers(delta):
            raise refuse("APPROVAL_DELTA_MISMATCH", "the approval names a different delta")
        return AdmissionDecision(
            admitted=True,
            reason_code="CAPABILITY_INCREASE_APPROVED",
            delta=delta,
            approval_digest=digest,
            baseline_digest=baseline_digest,
        )


# --- the people-facing operations: sign a baseline, grant an approval --------------------------


def sign_baseline(
    surface: CapabilitySurface,
    private_key: Ed25519PrivateKey,
    *,
    key_id: str,
    key_provenance: KeyProvenance,
    approver: str,
    derived_from: tuple[str, ...],
    rationale: str,
    baseline_id: str = "v1-capability-surface",
    now: datetime | None = None,
) -> CapabilityBaseline:
    baseline = CapabilityBaseline(
        baseline_id=baseline_id,
        surface=surface,
        derived_from=derived_from,
        approver=approver,
        key_id=key_id,
        key_provenance=key_provenance,
        issued_at=(now or datetime.now(UTC)).astimezone(UTC),
        rationale=rationale,
        signature="",
    )
    return sign_record(baseline, private_key)


def grant_approval(
    requested: AuthorizationManifest,
    report: ShadowReport,
    baseline: CapabilityBaseline,
    private_key: Ed25519PrivateKey,
    *,
    approver_key_id: str,
    approver: str,
    rationale: str,
    approval_id: str,
    ttl: timedelta = timedelta(hours=24),
    now: datetime | None = None,
) -> RiskApproval:
    """Sign an approval of ``requested``'s exact delta, on ``report``.

    Refuses (``ApprovalRefused``) before signing anything when the report was not produced on
    ``requested``'s shadow twin, when there is no increase to approve, or when the approver key
    would not be separate -- so a person cannot sign an approval admission would then refuse.
    """
    if requested.phase5 is None:
        raise ApprovalRefused("APPROVAL_REQUIRES_MANIFEST_15", "only a manifest 1.5 is approved")
    if requested.phase5.run_mode != "execute":
        raise ApprovalRefused("APPROVAL_FOR_SHADOW_MANIFEST", "approve the execute manifest")
    if report.manifest_digest != shadow_twin_digest(requested):
        raise ApprovalRefused(
            "APPROVAL_SHADOW_NOT_THIS_SURFACE",
            "the shadow report was not produced on this manifest's shadow twin",
        )
    delta = capability_delta(baseline.surface, requested)
    if not delta:
        raise ApprovalRefused("NO_CAPABILITY_INCREASE", "there is no increase to approve")
    try:
        require_key_separation(approver_key_id, requested)
    except SignedDocumentError as exc:
        raise ApprovalRefused(exc.reason_code, str(exc)) from exc
    if approver_key_id == baseline.key_id:
        raise ApprovalRefused("APPROVER_KEY_NOT_SEPARATE", "the approver key signed the baseline")
    issued = (now or datetime.now(UTC)).astimezone(UTC)
    approval = RiskApproval(
        approval_id=approval_id,
        engagement_id=requested.engagement_id,
        baseline_digest=baseline.baseline_digest(),
        manifest_surface_digest=requested.capability_surface_digest(),
        capability_delta=delta,
        shadow_report_digest=report.report_digest(),
        approver=approver,
        approver_key_id=approver_key_id,
        issued_at=issued,
        expires_at=issued + ttl,
        rationale=rationale,
        signature="",
    )
    return sign_record(approval, private_key)


def load_baseline(path: Path) -> CapabilityBaseline:
    return CapabilityBaseline.model_validate(json.loads(path.read_text(encoding="utf-8")))
