"""Frozen Phase 5 reference documents for the schema-drift gate (ADR 0013, plan §3).

Built entirely from constants, like the Phase 4 references in ``reporting.gates``, so their
canonical digests move only when a Phase 5 contract's canonical surface changes. The manifest 1.5
and scenario 1.4 references are derived from the Phase 4 references passed in, so the only
difference between, say, the 1.4 and 1.5 manifest references is the Phase 5 grant itself.

Signatures are left empty: every digest here excludes the signature field, exactly as the
manifest and attestation references do.
"""

from __future__ import annotations

from datetime import UTC, datetime

from purpleloop.schemas.action import BudgetRequest
from purpleloop.schemas.authorization import AuthorizationManifest
from purpleloop.schemas.phase1 import Phase1Scenario
from purpleloop.schemas.phase3 import DecodingParameters, ModelPin
from purpleloop.schemas.phase5 import (
    ActionClass,
    AdjudicationRecord,
    CapabilityIncrease,
    DefenseDependence,
    EvaluationMatrix,
    ImportSource,
    MatrixCell,
    MatrixRow,
    Phase5Grants,
    RiskApproval,
    ShadowReport,
)

_EPOCH = datetime(2026, 1, 1, tzinfo=UTC)
_DIGEST = "0" * 64


def reference_manifest_15(manifest_14: AuthorizationManifest) -> AuthorizationManifest:
    data = manifest_14.model_dump(mode="python", exclude_none=True)
    data["schema_version"] = "1.5.0"
    data["phase5"] = Phase5Grants(
        action_classes=frozenset({ActionClass.READ}),
        risk_approvals=frozenset({_DIGEST}),
        run_mode="shadow",
        matrix_scope=_DIGEST,
    )
    return AuthorizationManifest.model_validate(data)


def reference_scenario_14(scenario_13: Phase1Scenario) -> Phase1Scenario:
    data = scenario_13.model_dump(mode="python", exclude_none=True)
    data.update(
        schema_version="1.4.0",
        origin="imported",
        public_exposure=True,
        lane="agent",
        license="MIT",
        import_source=ImportSource(
            framework="agentdojo",
            upstream_version="reference-v1",
            upstream_commit="0" * 40,
            license="MIT",
            case_id="reference-case",
        ),
    )
    return Phase1Scenario.model_validate(data)


def reference_shadow_report() -> ShadowReport:
    return ShadowReport(
        run_id="reference-run",
        engagement_id="schema-reference",
        manifest_digest=_DIGEST,
        scenario_digests=(_DIGEST,),
        action_classes_reached=frozenset({ActionClass.READ, ActionClass.WRITE}),
        operations_proposed={"ticket.read": 2},
        denials_by_reason={"OPERATION_NOT_ALLOWED": 1},
        would_be_budget=BudgetRequest(requests=2, records=2),
        proposals_total=4,
        proposals_rejected=1,
        proposal_rejection_rate=0.25,
        suppressed_executions=2,
        unreachable_steps=1,
        created_at=_EPOCH,
    )


def reference_risk_approval() -> RiskApproval:
    return RiskApproval(
        approval_id="reference-approval",
        engagement_id="schema-reference",
        baseline_digest=_DIGEST,
        manifest_surface_digest=_DIGEST,
        capability_delta=frozenset({CapabilityIncrease.NEW_ACTION_CLASS}),
        shadow_report_digest=_DIGEST,
        approver="reference approver",
        approver_key_id="reference-approver-key",
        issued_at=_EPOCH,
        expires_at=datetime(2026, 1, 2, tzinfo=UTC),
        rationale="reference",
        signature="",
    )


def reference_matrix() -> EvaluationMatrix:
    return EvaluationMatrix(
        matrix_id="reference-matrix",
        engagement_id="schema-reference",
        rows=(
            MatrixRow(
                row_id="reference-blind",
                kind="deterministic-anchor",
                anchor="delimitation-blind",
                pin=ModelPin(
                    pin_id="reference-pin",
                    provider="offline",
                    model_id="reference-model",
                    decoding=DecodingParameters(seed=1),
                    system_prompt_hash=_DIGEST,
                ),
                seeds=(1, 2, 3, 4, 5),
                decoding_label="greedy",
            ),
        ),
        defense_columns=("no-defense", "reference-defense"),
        baseline_column="no-defense",
        scenario_ids=frozenset({"schema-reference"}),
        repetitions=5,
        cost_cap_microusd=0,
        alpha=0.05,
        issued_at=_EPOCH,
        key_id="reference-key",
        signature="",
    )


def reference_matrix_cell() -> MatrixCell:
    return MatrixCell(
        matrix_digest=_DIGEST,
        row_id="reference-blind",
        defense_column="reference-defense",
        scenario_id="schema-reference",
        successes=1,
        n=5,
        value=0.2,
        ci_low=0.0,
        ci_high=0.6,
        model_pin_id="reference-pin",
        seed_policy="fixed-per-repetition",
    )


def reference_defense_dependence() -> DefenseDependence:
    return DefenseDependence(
        matrix_digest=_DIGEST,
        defense_column="reference-defense",
        scenario_id="schema-reference",
        enforcement="application-side",
        classification="model-independent",
        credited_rows=frozenset({"reference-blind"}),
        uncredited_rows=frozenset(),
        delimitation_blind_row="reference-blind",
        trials=5,
    )


def reference_adjudication() -> AdjudicationRecord:
    return AdjudicationRecord(
        finding_id="reference-finding",
        bundle_digest=_DIGEST,
        label="true-positive",
        rationale="reference",
        cited_evidence_ids=("reference-evidence",),
        blinded=True,
        reviewer_key_id="reference-reviewer-key",
        recorded_at=_EPOCH,
        signature="",
    )


def phase5_schema_digests(
    manifest_14: AuthorizationManifest, scenario_13: Phase1Scenario
) -> dict[str, str]:
    """Canonical digests of every Phase 5 reference document, keyed like the Phase 4 ones."""
    return {
        "authorization-manifest-1.5": reference_manifest_15(manifest_14).manifest_digest(),
        "scenario-1.4": reference_scenario_14(scenario_13).digest(),
        "shadow-report-1.0": reference_shadow_report().report_digest(),
        "risk-approval-1.0": reference_risk_approval().approval_digest(),
        "evaluation-matrix-1.0": reference_matrix().matrix_digest(),
        "matrix-cell-1.0": reference_matrix_cell().digest(),
        "defense-dependence-1.0": reference_defense_dependence().digest(),
        "adjudication-record-1.0": reference_adjudication().record_digest(),
    }
