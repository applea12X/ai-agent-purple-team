"""Admission enforcement (WP5.1.4-5.1.5): an uncovered capability increase is refused.

Each refusal asserts its reason code, so a check that refuses for the wrong reason does not
pass. The end-to-end cases run the real paired runner and read the refusal back out of the
audit export, which is where the plan requires it to be evidence.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from ipaddress import IPv4Address
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from purpleloop.control.approvals import (
    ApprovalAdmission,
    ApprovalRefused,
    shadow_twin,
    shadow_twin_digest,
    with_approvals,
)
from purpleloop.control.capabilities import capability_delta
from purpleloop.control.phase5_signing import sign_record
from purpleloop.reporting.audit_export import export_audit
from purpleloop.runtime.governance import (
    ATTESTATION_KEY_ID,
    agent_manifest_15,
    sign_v1_baseline,
    v1_lane_manifests,
)
from purpleloop.schemas.authorization import AuthorizationManifest
from purpleloop.schemas.event import EventKind
from purpleloop.schemas.phase5 import (
    CAPABILITY_INCREASES,
    ActionClass,
    CapabilityIncrease,
    RiskApproval,
    ShadowReport,
)

Kind = CapabilityIncrease
NOW = datetime.now(UTC)


def widened(governance: Any, kind: Kind, **extra: Any) -> AuthorizationManifest:
    """A 1.5 agent manifest widened along exactly one increase kind."""
    base = governance.manifest(**extra)
    options: dict[str, Any] = dict(extra)
    if kind == Kind.NEW_ACTION_CLASS:
        options["action_classes"] = (ActionClass.READ, ActionClass.WRITE, ActionClass.CODE_EXEC)
    elif kind == Kind.NEW_ADAPTER_OR_OPERATION:
        options["overrides"] = {"allowed_operations": base.allowed_operations | {"snippet.run"}}
    elif kind == Kind.NEW_TARGET_FIXTURE:
        new_asset = {
            "asset_id": "codelab-data",
            "scheme": "http",
            "host": "127.0.0.1",
            "port": 38080,
            "tenant_ids": frozenset({"org-a"}),
            "allowed_resolved_addresses": frozenset({IPv4Address("127.0.0.1")}),
        }
        options["overrides"] = {
            "assets": (*(a.model_dump(mode="python") for a in base.assets), new_asset)
        }
    elif kind == Kind.WIDENED_EGRESS:
        options["overrides"] = {"egress_hosts": base.egress_hosts | {"10.0.0.1"}}
    elif kind == Kind.RAISED_ATTACKER_CAPS:
        options["phase3_overrides"] = {"max_attacker_proposals": 16}
    else:
        options["proposal_source"] = "model-driven"
    manifest = governance.manifest(**options)
    assert capability_delta(governance.baseline.surface, manifest) == frozenset({kind})
    return manifest


def report_for(requested: AuthorizationManifest, make_shadow_report: Callable[..., Any]) -> Any:
    return make_shadow_report(
        engagement_id=requested.engagement_id,
        manifest_digest=shadow_twin_digest(requested),
        created_at=NOW - timedelta(minutes=5),
    )


def approve(governance: Any, requested: AuthorizationManifest, report: Any, **kw: Any) -> Any:
    """Grant at a fixed instant just before ``NOW``, so window checks are deterministic."""
    return governance.approve(requested, report, now=NOW - timedelta(minutes=1), **kw)


def resign(approval: RiskApproval, key: Ed25519PrivateKey, **update: Any) -> RiskApproval:
    data = approval.model_dump(mode="python")
    data.update(update, signature="")
    return sign_record(RiskApproval.model_validate(data), key)


# --- the four admission outcomes ------------------------------------------------------------------


def test_v1_manifests_are_admitted_with_nothing_to_approve(governance: Any, tmp_path: Path) -> None:
    for manifest in v1_lane_manifests():
        decision = governance.admission().admit(manifest, now=NOW)
        assert decision.admitted and decision.reason_code == "PRE_PHASE5_SURFACE"
    # Even with no admission configured at all, a pre-1.5 run-level admission records nothing.
    runner = governance.agent_runner(v1_lane_manifests()[2], tmp_path, None)
    assert runner.runtime.admit(v1_lane_manifests()[2], run_id="r", trace_id="t") is None


def test_a_15_manifest_inside_the_baseline_needs_no_approval(governance: Any) -> None:
    decision = governance.admission().admit(governance.manifest(), now=NOW)
    assert decision.admitted and decision.reason_code == "NO_CAPABILITY_INCREASE"
    assert decision.delta == frozenset()


@pytest.mark.parametrize("kind", CAPABILITY_INCREASES, ids=lambda kind: kind.value)
def test_each_uncovered_increase_kind_is_refused(governance: Any, kind: Kind) -> None:
    manifest = widened(governance, kind)
    with pytest.raises(ApprovalRefused) as refused:
        governance.admission().admit(manifest, now=NOW)
    assert refused.value.reason_code == "CAPABILITY_INCREASE_UNAPPROVED"
    assert refused.value.delta == frozenset({kind})
    # Its shadow twin is admitted, delta recorded: shadow is how the evidence is produced.
    twin = governance.admission().admit(shadow_twin(manifest), now=NOW)
    assert twin.admitted and twin.reason_code == "SHADOW_ADMITTED" and twin.delta == {kind}


@pytest.mark.parametrize("kind", CAPABILITY_INCREASES, ids=lambda kind: kind.value)
def test_each_increase_kind_is_admitted_with_its_exact_approval(
    governance: Any, kind: Kind, make_shadow_report: Callable[..., Any]
) -> None:
    requested = widened(governance, kind)
    report = report_for(requested, make_shadow_report)
    approval = approve(governance, requested, report)
    assert approval.capability_delta == frozenset({kind})
    manifest = governance.approved(requested, approval)
    decision = governance.admission([approval], [report]).admit(manifest, now=NOW)
    assert decision.admitted and decision.reason_code == "CAPABILITY_INCREASE_APPROVED"
    assert decision.approval_digest == approval.approval_digest()
    assert decision.baseline_digest == governance.baseline.baseline_digest()


# --- refusals, one reason code each ---------------------------------------------------------------


@pytest.fixture
def approved_case(
    governance: Any, make_shadow_report: Callable[..., Any]
) -> tuple[AuthorizationManifest, RiskApproval, ShadowReport]:
    requested = widened(governance, Kind.PROPOSAL_SOURCE_CHANGE)
    report = report_for(requested, make_shadow_report)
    return requested, approve(governance, requested, report), report


def refusal(governance: Any, manifest: AuthorizationManifest, admission: Any, **kw: Any) -> str:
    with pytest.raises(ApprovalRefused) as refused:
        admission.admit(manifest, now=kw.get("now", NOW))
    return refused.value.reason_code


def test_a_named_approval_that_is_not_available_is_refused(
    governance: Any, approved_case: Any
) -> None:
    requested, approval, report = approved_case
    manifest = governance.approved(requested, approval)
    assert refusal(governance, manifest, governance.admission([], [report])) == (
        "APPROVAL_NOT_FOUND"
    )


def test_an_approval_without_its_shadow_report_is_refused(
    governance: Any, approved_case: Any
) -> None:
    requested, approval, _ = approved_case
    manifest = governance.approved(requested, approval)
    assert refusal(governance, manifest, governance.admission([approval], [])) == (
        "APPROVAL_SHADOW_REPORT_MISSING"
    )


def test_two_approvals_are_ambiguous(governance: Any, approved_case: Any) -> None:
    requested, approval, report = approved_case
    second = resign(approval, governance.approver_key, approval_id="approval-second")
    manifest = governance.approved(requested, approval, second)
    admission = governance.admission([approval, second], [report])
    assert refusal(governance, manifest, admission) == "APPROVAL_AMBIGUOUS"


def test_an_approval_named_for_no_increase_is_refused(governance: Any, approved_case: Any) -> None:
    _, approval, report = approved_case
    plain = governance.approved(governance.manifest(), approval)
    assert refusal(governance, plain, governance.admission([approval], [report])) == (
        "APPROVAL_DELTA_MISMATCH"
    )


@pytest.mark.parametrize(
    "delta",
    [
        frozenset({Kind.PROPOSAL_SOURCE_CHANGE, Kind.NEW_ACTION_CLASS}),
        frozenset({Kind.RAISED_ATTACKER_CAPS}),
    ],
    ids=["superset", "different"],
)
def test_an_approval_naming_a_different_delta_is_refused(
    governance: Any, approved_case: Any, delta: frozenset[Kind]
) -> None:
    requested, approval, report = approved_case
    changed = resign(approval, governance.approver_key, capability_delta=delta)
    manifest = governance.approved(requested, changed)
    assert refusal(governance, manifest, governance.admission([changed], [report])) == (
        "APPROVAL_DELTA_MISMATCH"
    )


def test_an_approval_does_not_cover_a_further_widening(governance: Any, approved_case: Any) -> None:
    """Approved for the model-driven source; the manifest then also raises the attacker caps."""
    requested, approval, report = approved_case
    wider = governance.manifest(
        proposal_source="model-driven", phase3_overrides={"max_attacker_proposals": 16}
    )
    manifest = governance.approved(wider, approval)
    # The surface digest moved, so the approval no longer names this manifest at all.
    assert refusal(governance, manifest, governance.admission([approval], [report])) == (
        "APPROVAL_MANIFEST_MISMATCH"
    )


@pytest.mark.parametrize(
    ("when", "reason"),
    [(timedelta(hours=25), "APPROVAL_EXPIRED"), (timedelta(hours=-1), "APPROVAL_NOT_YET_VALID")],
)
def test_an_approval_outside_its_window_is_refused(
    governance: Any, approved_case: Any, when: timedelta, reason: str
) -> None:
    requested, approval, report = approved_case
    manifest = governance.approved(requested, approval)
    admission = governance.admission([approval], [report])
    assert refusal(governance, manifest, admission, now=NOW + when) == reason


def test_an_untrusted_or_tampered_approval_is_refused(governance: Any, approved_case: Any) -> None:
    requested, approval, report = approved_case
    manifest = governance.approved(requested, approval)
    stranger = governance.admission([approval], [report], approver_keys={})
    assert refusal(governance, manifest, stranger) == "UNKNOWN_SIGNING_KEY"
    forged = resign(approval, Ed25519PrivateKey.generate())
    manifest = governance.approved(requested, forged)
    assert refusal(governance, manifest, governance.admission([forged], [report])) == (
        "INVALID_SIGNATURE"
    )


@pytest.mark.parametrize("role", ["attestation", "manifest", "baseline"])
def test_an_approver_key_that_holds_another_role_is_refused(
    governance: Any, approved_case: Any, role: str
) -> None:
    requested, approval, report = approved_case
    key_id = {
        "attestation": ATTESTATION_KEY_ID,
        "manifest": requested.key_id,
        "baseline": governance.baseline.key_id,
    }[role]
    shared = resign(approval, governance.approver_key, approver_key_id=key_id)
    manifest = governance.approved(requested, shared)
    admission = governance.admission(
        [shared], [report], approver_keys={key_id: governance.approver_key.public_key()}
    )
    assert refusal(governance, manifest, admission) == "APPROVER_KEY_NOT_SEPARATE"
    with pytest.raises(ApprovalRefused) as refused:
        approve(governance, requested, report, approver_key_id=key_id)
    assert refused.value.reason_code == "APPROVER_KEY_NOT_SEPARATE"


def test_an_approval_against_another_baseline_is_refused(
    governance: Any, approved_case: Any
) -> None:
    requested, approval, report = approved_case
    other = resign(approval, governance.approver_key, baseline_digest="c" * 64)
    manifest = governance.approved(requested, other)
    assert refusal(governance, manifest, governance.admission([other], [report])) == (
        "APPROVAL_BASELINE_MISMATCH"
    )


def test_a_shadow_report_from_another_surface_is_refused(
    governance: Any, approved_case: Any, make_shadow_report: Callable[..., Any]
) -> None:
    requested, approval, _ = approved_case
    elsewhere = make_shadow_report(
        engagement_id=requested.engagement_id, created_at=NOW - timedelta(minutes=5)
    )
    rebound = resign(
        approval, governance.approver_key, shadow_report_digest=elsewhere.report_digest()
    )
    manifest = governance.approved(requested, rebound)
    admission = governance.admission([rebound], [elsewhere])
    assert refusal(governance, manifest, admission) == "APPROVAL_SHADOW_NOT_THIS_SURFACE"
    with pytest.raises(ApprovalRefused) as refused:
        approve(governance, requested, elsewhere)
    assert refused.value.reason_code == "APPROVAL_SHADOW_NOT_THIS_SURFACE"


def test_an_approval_for_another_engagement_is_refused(governance: Any, approved_case: Any) -> None:
    requested, approval, report = approved_case
    moved = resign(approval, governance.approver_key, engagement_id="another-engagement")
    manifest = governance.approved(requested, moved)
    assert refusal(governance, manifest, governance.admission([moved], [report])) == (
        "APPROVAL_ENGAGEMENT_MISMATCH"
    )


def test_an_untrusted_or_tampered_baseline_is_refused(governance: Any, approved_case: Any) -> None:
    requested, approval, report = approved_case
    manifest = governance.approved(requested, approval)
    other_baseline, _ = sign_v1_baseline()
    wrong_key = ApprovalAdmission.of(other_baseline, governance.baseline_keys)
    assert refusal(governance, manifest, wrong_key) == "BASELINE_INVALID_SIGNATURE"
    unknown = ApprovalAdmission.of(governance.baseline, {})
    assert refusal(governance, manifest, unknown) == "BASELINE_UNKNOWN_SIGNING_KEY"
    # A baseline edited to include the increase -- the obvious way around admission -- fails
    # its own signature check before any delta is computed.
    widened_surface = governance.baseline.surface.model_copy(
        update={"proposal_source": "model-driven"}
    )
    edited = governance.baseline.model_copy(update={"surface": widened_surface})
    edited_admission = ApprovalAdmission.of(edited, governance.baseline_keys)
    assert refusal(governance, requested, edited_admission) == "BASELINE_INVALID_SIGNATURE"


def test_grant_refuses_what_admission_would_refuse(
    governance: Any, make_shadow_report: Callable[..., Any]
) -> None:
    plain = governance.manifest()
    report = report_for(plain, make_shadow_report)
    with pytest.raises(ApprovalRefused) as nothing:
        approve(governance, plain, report)
    assert nothing.value.reason_code == "NO_CAPABILITY_INCREASE"
    shadow = shadow_twin(widened(governance, Kind.NEW_ACTION_CLASS))
    with pytest.raises(ApprovalRefused) as mode:
        approve(governance, shadow, report)
    assert mode.value.reason_code == "APPROVAL_FOR_SHADOW_MANIFEST"
    with pytest.raises(ApprovalRefused) as legacy:
        approve(governance, v1_lane_manifests()[2], report)
    assert legacy.value.reason_code == "APPROVAL_REQUIRES_MANIFEST_15"
    with pytest.raises(ValueError):
        shadow_twin(v1_lane_manifests()[2])
    with pytest.raises(ValueError):
        with_approvals(v1_lane_manifests()[2], [])


def test_a_15_manifest_without_configured_admission_is_refused(
    governance: Any, tmp_path: Path
) -> None:
    runner = governance.agent_runner(governance.manifest(), tmp_path, None)
    with pytest.raises(ApprovalRefused) as refused:
        runner.runtime.admit(governance.manifest(), run_id="r", trace_id="t")
    assert refused.value.reason_code == "APPROVAL_ADMISSION_UNCONFIGURED"


def test_approvals_do_not_change_the_capability_surface_digest(
    governance: Any, approved_case: Any
) -> None:
    requested, approval, _ = approved_case
    manifest = governance.approved(requested, approval)
    assert manifest.capability_surface_digest() == requested.capability_surface_digest()
    assert shadow_twin_digest(manifest) == shadow_twin_digest(requested)


# --- the runtime enforces it on every action, and mid-run --------------------------------------


def test_an_approval_expiring_mid_run_fails_closed_at_the_next_action(
    governance: Any, approved_case: Any, tmp_path: Path
) -> None:
    requested, _, report = approved_case
    # Shorter than the manifest's own two-hour window, so the approval is what expires.
    approval = approve(governance, requested, report, ttl=timedelta(minutes=30))
    manifest = governance.approved(requested, approval)
    runner = governance.agent_runner(manifest, tmp_path, governance.admission([approval], [report]))
    runtime = runner.runtime
    instant = [NOW]
    runtime.clock = lambda: instant[0]
    from purpleloop.runtime.fixture import FixtureController

    controller = FixtureController(
        runtime,
        manifest,
        "expiry",
        tools=runner.lane.tools,
        control_asset_id=runner.lane.control_asset_id,
        credential_handle=runner.lane.control_credential_handle,
    )
    first = asyncio.run(
        runtime.run(manifest, controller.action_for("provision"), run_id="expiry", trace_id="1")
    )
    assert first.status == "completed"
    instant[0] = approval.expires_at
    second = asyncio.run(
        runtime.run(manifest, controller.action_for("seed"), run_id="expiry", trace_id="2")
    )
    assert (second.status, second.reason_code) == ("denied", "APPROVAL_EXPIRED")
    events = runtime.ledger.verify()
    assert events[-1].kind == EventKind.ADMISSION and events[-1].decision == "deny"


@pytest.mark.parametrize("kind", CAPABILITY_INCREASES, ids=lambda kind: kind.value)
def test_each_refusal_is_evidence_in_the_audit_export(
    governance: Any, kind: Kind, tmp_path: Path
) -> None:
    """End to end: the paired runner refuses at admission; nothing reaches the fixture."""
    from purpleloop.schemas.phase1 import load_scenario

    manifest = widened(governance, kind)
    bundle = tmp_path / "bundle"
    runner = governance.agent_runner(manifest, bundle, governance.admission())
    scenario = load_scenario(
        Path(__file__).parents[2] / "scenarios" / "agent" / "agent-tool-misuse.yaml"
    )
    summary = asyncio.run(runner.run(scenario, manifest, run_id="refused", output_dir=bundle))
    # The run ends with the admission reason. Teardown is refused too -- under a refused
    # manifest nothing runs, not even cleanup of a fixture that was never provisioned -- and the
    # runner appends that, exactly as it does for any other admission failure.
    assert summary.status == "error"
    assert summary.reason.split(";")[0] == "CAPABILITY_INCREASE_UNAPPROVED"
    assert governance.counts["fixture-requests"] == 0
    assert governance.counts["model-calls"] == 0
    export = export_audit(bundle, tmp_path / "audit.json")
    decisions = export["runs"][0]["decisions"]
    refusals = [
        d
        for d in decisions
        if d["kind"] == "admission" and d["reason_code"] == "CAPABILITY_INCREASE_UNAPPROVED"
    ]
    assert refusals and refusals[0]["decision"] == "deny"
    assert not any(d["kind"] == "admission" and d["decision"] == "permit" for d in decisions)
    raw = json.loads((tmp_path / "audit.json").read_text())
    assert raw["runs"][0]["reason"].startswith("CAPABILITY_INCREASE_UNAPPROVED")


# --- properties ---------------------------------------------------------------------------------

kinds = st.sets(st.sampled_from(CAPABILITY_INCREASES), min_size=1)
SETTINGS = settings(max_examples=40, deadline=None, suppress_health_check=[HealthCheck.too_slow])


def multi_widened(base_key: Ed25519PrivateKey, chosen: set[Kind]) -> AuthorizationManifest:
    base = agent_manifest_15(base_key)
    overrides: dict[str, Any] = {}
    options: dict[str, Any] = {}
    if Kind.NEW_ACTION_CLASS in chosen:
        options["action_classes"] = (ActionClass.READ, ActionClass.WRITE, ActionClass.CODE_EXEC)
    if Kind.NEW_ADAPTER_OR_OPERATION in chosen:
        overrides["allowed_adapters"] = base.allowed_adapters | {"sandbox"}
    if Kind.NEW_TARGET_FIXTURE in chosen:
        assets = [a.model_dump(mode="python") for a in base.assets]
        assets[0]["tenant_ids"] = frozenset(assets[0]["tenant_ids"]) | {"org-c"}
        overrides["assets"] = tuple(assets)
    if Kind.WIDENED_EGRESS in chosen:
        overrides["egress_hosts"] = base.egress_hosts | {"10.0.0.1"}
    if Kind.RAISED_ATTACKER_CAPS in chosen:
        options["phase3_overrides"] = {"max_attacker_depth": 8}
    if Kind.PROPOSAL_SOURCE_CHANGE in chosen:
        options["proposal_source"] = "model-driven"
    return agent_manifest_15(base_key, overrides=overrides, **options)


PROPERTY_KEY = Ed25519PrivateKey.generate()
APPROVER = Ed25519PrivateKey.generate()
PROPERTY_BASELINE, PROPERTY_PEM = sign_v1_baseline()


def _admission(approvals: Any = (), reports: Any = ()) -> ApprovalAdmission:
    from cryptography.hazmat.primitives.serialization import load_pem_public_key

    return ApprovalAdmission.of(
        PROPERTY_BASELINE,
        {PROPERTY_BASELINE.key_id: load_pem_public_key(PROPERTY_PEM)},  # type: ignore[dict-item]
        approver_keys={"approver-ephemeral": APPROVER.public_key()},
        approvals=approvals,
        shadow_reports=reports,
    )


def _report(requested: AuthorizationManifest) -> ShadowReport:
    from purpleloop.schemas.action import BudgetRequest

    return ShadowReport(
        run_id="property-shadow",
        engagement_id=requested.engagement_id,
        manifest_digest=shadow_twin_digest(requested),
        action_classes_reached=frozenset({ActionClass.READ}),
        would_be_budget=BudgetRequest(requests=1, records=1),
        proposals_total=0,
        proposals_rejected=0,
        proposal_rejection_rate=0.0,
        suppressed_executions=1,
        unreachable_steps=0,
        created_at=NOW - timedelta(minutes=1),
    )


def _approval(requested: AuthorizationManifest, delta: frozenset[Kind]) -> RiskApproval:
    approval = RiskApproval(
        approval_id="property-approval",
        engagement_id=requested.engagement_id,
        baseline_digest=PROPERTY_BASELINE.baseline_digest(),
        manifest_surface_digest=requested.capability_surface_digest(),
        capability_delta=delta,
        shadow_report_digest=_report(requested).report_digest(),
        approver="property approver",
        approver_key_id="approver-ephemeral",
        issued_at=NOW - timedelta(minutes=1),
        expires_at=NOW + timedelta(hours=1),
        rationale="property",
        signature="",
    )
    return sign_record(approval, APPROVER)


@SETTINGS
@given(kinds)
def test_any_widening_is_refused_without_an_approval(chosen: set[Kind]) -> None:
    requested = multi_widened(PROPERTY_KEY, chosen)
    assert capability_delta(PROPERTY_BASELINE.surface, requested) == frozenset(chosen)
    decision = _admission().decide(requested, now=NOW)
    assert not decision.admitted and decision.reason_code == "CAPABILITY_INCREASE_UNAPPROVED"


@SETTINGS
@given(kinds, kinds)
def test_only_the_exact_delta_is_admitted(chosen: set[Kind], approved: set[Kind]) -> None:
    requested = multi_widened(PROPERTY_KEY, chosen)
    approval = _approval(requested, frozenset(approved))
    manifest = with_approvals(requested, [approval])
    decision = _admission([approval], [_report(requested)]).decide(manifest, now=NOW)
    if approved == chosen:
        assert decision.admitted and decision.reason_code == "CAPABILITY_INCREASE_APPROVED"
    else:
        assert not decision.admitted and decision.reason_code == "APPROVAL_DELTA_MISMATCH"


@SETTINGS
@given(st.sets(st.sampled_from(["budget", "window", "shadow", "fewer-ops"]), min_size=1))
def test_narrowing_and_non_capability_changes_never_need_an_approval(changes: set[str]) -> None:
    base = agent_manifest_15(PROPERTY_KEY)
    overrides: dict[str, Any] = {}
    if "budget" in changes:
        overrides["budgets"] = base.budgets.model_copy(update={"requests": 9999})
    if "window" in changes:
        overrides["valid_until"] = base.valid_until + timedelta(days=30)
    if "fewer-ops" in changes:
        overrides["allowed_operations"] = base.allowed_operations - {"email.send"}
    manifest = agent_manifest_15(
        PROPERTY_KEY,
        overrides=overrides,
        run_mode="shadow" if "shadow" in changes else "execute",
    )
    decision = _admission().decide(manifest, now=NOW)
    assert decision.admitted and decision.delta == frozenset()
