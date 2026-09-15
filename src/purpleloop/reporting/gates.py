"""The five enforcing CI gates, as pure decision functions (ADR 0013).

Each gate is data-in / typed-decision-out: CI calls exactly the functions the unit tests call,
so the red-branch protocol proves the wiring and the unit tests prove the logic, and neither
substitutes for the other. Every input that carries a verdict is checked by ``require_binding``
first -- an advisory or pinned-stochastic value cannot reach a gate by being averaged in,
because it is rejected at the type boundary before any arithmetic happens.

A gate that blocks names its reason; a gate that passes says what it examined. A gate handed
nothing to examine blocks rather than passing vacuously, because "the gate saw no evidence" and
"the evidence was clean" are different facts.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from ipaddress import IPv4Address
from pathlib import Path

from purpleloop.schemas.action import SideEffectClass
from purpleloop.schemas.authorization import (
    AssetScope,
    AuthorizationManifest,
    BudgetLimits,
    Phase1Grants,
)
from purpleloop.schemas.event import EventKind, EvidenceEvent
from purpleloop.schemas.phase1 import (
    Actor,
    DetectorResult,
    Finding,
    LegResult,
    OracleResult,
    OracleSpec,
    Phase1Scenario,
    RunSummary,
    Step,
)
from purpleloop.schemas.phase2 import OwnershipScope, Phase2Grants
from purpleloop.schemas.phase3 import (
    AgentTask,
    DecodingParameters,
    ModelPin,
    Phase3Grants,
    require_binding,
)
from purpleloop.schemas.phase4 import (
    AttestationMaterials,
    GateDecision,
    NightlyScope,
    Phase4Grants,
    RegressionRegistry,
    RetentionRule,
    RiskClassBaseline,
    RiskClassMetrics,
    RunAttestation,
)
from purpleloop.scoring.phase4 import PREREGISTERED_ALPHA, compare_risk_classes

#: Event kinds whose decision guards an action before its result exists.
GUARD_KINDS = frozenset({EventKind.ADMISSION, EventKind.POLICY, EventKind.BUDGET})


def scope_gate(events: Sequence[EvidenceEvent]) -> GateDecision:
    """Block on any executed result whose action was not affirmatively permitted.

    The ledger invariant this checks: every ``RESULT`` event with decision ``permit`` (an
    execution that completed) must be preceded by a ``POLICY`` permit for the same action
    digest, and no guard denial for that digest may be the latest guard decision before it.
    A permit-less execution, or an execution after a standing denial, is a scope bypass.
    """
    if not events:
        return GateDecision(
            gate="scope-bypass",
            blocked=True,
            reason_code="NO_EVIDENCE",
            detail="no events were provided; an empty ledger is not a clean ledger",
        )
    violations: list[str] = []
    guard_history: dict[str, list[tuple[int, str]]] = {}
    executed = 0
    for event in events:
        digest = event.action_digest
        if digest is None:
            continue
        if event.kind in GUARD_KINDS and event.decision is not None:
            guard_history.setdefault(digest, []).append((event.sequence, event.decision))
        if event.kind == EventKind.RESULT and event.decision == "permit":
            executed += 1
            prior = [item for item in guard_history.get(digest, []) if item[0] < event.sequence]
            if not any(decision == "permit" for _, decision in prior):
                violations.append(f"seq {event.sequence}: executed without a policy permit")
            elif prior and prior[-1][1] == "deny":
                violations.append(f"seq {event.sequence}: executed after a standing denial")
    if violations:
        return GateDecision(
            gate="scope-bypass",
            blocked=True,
            reason_code="SCOPE_BYPASS",
            detail="; ".join(violations[:20]),
        )
    return GateDecision(
        gate="scope-bypass",
        blocked=False,
        reason_code="NO_BYPASS_OBSERVED",
        detail=f"{executed} executed results, each preceded by a policy permit",
    )


def budget_gate(
    events: Sequence[EvidenceEvent],
    limits: BudgetLimits,
    summaries: Sequence[RunSummary],
) -> GateDecision:
    """Block on budget arithmetic failure or on an execution after a budget denial.

    Two checks: no summary's recorded budget use may exceed the signed limits, and no
    ``RESULT`` permit may follow a ``BUDGET`` denial for the same action digest. A breach that
    is recorded as a budget outcome and stops the run is correct behaviour, not a violation.
    """
    violations: list[str] = []
    for summary in summaries:
        used = summary.budget_used
        for name in ("requests", "writes", "records", "tokens", "cost_microusd"):
            charged = getattr(used, name)
            limit = getattr(limits, name)
            if charged > limit:
                violations.append(
                    f"{summary.run_id}: {name} charged {charged} over signed limit {limit}"
                )
    budget_denied_at: dict[str, int] = {}
    for event in events:
        digest = event.action_digest
        if digest is None:
            continue
        if event.kind == EventKind.BUDGET and event.decision == "deny":
            budget_denied_at[digest] = event.sequence
        if (
            event.kind == EventKind.RESULT
            and event.decision == "permit"
            and digest in budget_denied_at
            and budget_denied_at[digest] < event.sequence
        ):
            violations.append(f"seq {event.sequence}: executed after a budget denial")
    if violations:
        return GateDecision(
            gate="budget-failure",
            blocked=True,
            reason_code="BUDGET_VIOLATION",
            detail="; ".join(violations[:20]),
        )
    return GateDecision(
        gate="budget-failure",
        blocked=False,
        reason_code="BUDGETS_HELD",
        detail=f"{len(summaries)} run(s) within signed limits; no post-denial execution",
    )


def critical_regression_gate(
    registry: RegressionRegistry, outcomes: Mapping[str, bool]
) -> GateDecision:
    """Block when a registry-covered finding's pinning test failed or did not run.

    ``outcomes`` maps pytest node ids to pass/fail, usually parsed from a JUnit report of the
    suite that just ran. A covered test missing from the report blocks: "the test did not run"
    and "the test passed" are different facts.
    """
    covered = registry.covered()
    failed = [entry.finding_class for entry in covered if outcomes.get(entry.test) is False]
    missing = [entry.finding_class for entry in covered if entry.test not in outcomes]
    if failed:
        return GateDecision(
            gate="critical-regression",
            blocked=True,
            reason_code="REGISTRY_TEST_FAILED",
            detail="failed pinning tests for: " + ", ".join(sorted(failed)[:20]),
        )
    if missing:
        return GateDecision(
            gate="critical-regression",
            blocked=True,
            reason_code="REGISTRY_TEST_NOT_RUN",
            detail="pinning tests absent from the report for: " + ", ".join(sorted(missing)[:20]),
        )
    return GateDecision(
        gate="critical-regression",
        blocked=False,
        reason_code="REGISTRY_TESTS_PASSED",
        detail=f"{len(registry.covered())} covered finding(s), every pinning test passed",
    )


def schema_drift_gate(baseline: Mapping[str, str], observed: Mapping[str, str]) -> GateDecision:
    """Block when any canonical reference digest differs from the committed baseline.

    The observed digests come from :func:`schema_digests`: frozen reference documents built
    entirely from constants, so their canonical bytes change only when serialization or a
    schema's canonical surface changes. New reference names also block, forcing a deliberate,
    reviewed baseline-bump commit rather than a silent widening.
    """
    drifted = sorted(
        name for name in baseline if name in observed and observed[name] != baseline[name]
    )
    missing = sorted(name for name in baseline if name not in observed)
    unrecorded = sorted(name for name in observed if name not in baseline)
    if drifted or missing or unrecorded:
        parts = []
        if drifted:
            parts.append("drifted: " + ", ".join(drifted))
        if missing:
            parts.append("missing from observed: " + ", ".join(missing))
        if unrecorded:
            parts.append("not in baseline (bump required): " + ", ".join(unrecorded))
        return GateDecision(
            gate="schema-drift",
            blocked=True,
            reason_code="SCHEMA_DIGEST_DRIFT",
            detail="; ".join(parts),
        )
    return GateDecision(
        gate="schema-drift",
        blocked=False,
        reason_code="CANONICAL_BYTES_STABLE",
        detail=f"{len(baseline)} reference digest(s) unchanged",
    )


def risk_class_gate(
    baseline: RiskClassBaseline,
    current: Sequence[RiskClassMetrics],
    *,
    alpha: float = PREREGISTERED_ALPHA,
) -> GateDecision:
    """Block on the pre-registered per-risk-class regression test (scoring.phase4)."""
    comparisons = compare_risk_classes(baseline, current, alpha=alpha)
    blocked = [item for item in comparisons if item.blocked]
    if blocked:
        return GateDecision(
            gate="risk-class-regression",
            blocked=True,
            reason_code="RISK_CLASS_REGRESSION",
            detail="; ".join(
                f"{item.risk_class}: {item.reason_code}"
                + (f" (p={item.p_value})" if item.p_value is not None else "")
                for item in blocked[:20]
            ),
        )
    return GateDecision(
        gate="risk-class-regression",
        blocked=False,
        reason_code="WITHIN_BASELINE",
        detail=f"{len(comparisons)} class(es) compared at alpha={alpha}",
    )


def outcomes_from_junit(path: Path) -> dict[str, bool]:
    """Pytest node id -> passed, parsed from a JUnit XML report.

    JUnit records the module as a dotted classname; the node id is rebuilt as
    ``path/to/test.py::function``. A skipped test is recorded as not-passed rather than
    dropped, so a covered test that was skipped blocks the critical-regression gate.
    """
    outcomes: dict[str, bool] = {}
    root = ET.parse(path).getroot()  # noqa: S314 -- local CI artifact, not untrusted input
    for case in root.iter("testcase"):
        classname = case.get("classname", "")
        name = case.get("name", "")
        if not classname or not name:
            continue
        module = classname.replace(".", "/") + ".py"
        # Parametrized ids keep their brackets; a class-based test keeps its class segment.
        node = f"{module}::{name}"
        failed = case.find("failure") is not None or case.find("error") is not None
        skipped = case.find("skipped") is not None
        outcomes[node] = not failed and not skipped
    return outcomes


# --- frozen reference documents for the schema-drift gate -------------------------------------

_EPOCH = datetime(2026, 1, 1, tzinfo=UTC)
_DIGEST = "0" * 64
_COMMIT = "0" * 40


def _reference_manifest(version: str) -> AuthorizationManifest:
    phase4 = (
        Phase4Grants(
            attestation_key_ids=frozenset({"reference-key"}),
            retention=(
                RetentionRule(artifact_kind="raw-ledgers", days=0, rationale="reference document"),
            ),
            nightly_scope=NightlyScope(
                scenario_ids=frozenset({"reference-scenario"}), repetitions=5
            ),
        )
        if version == "1.4.0"
        else None
    )
    return AuthorizationManifest(
        schema_version=version,  # type: ignore[arg-type]
        engagement_id="schema-reference",
        owner="reference-owner",
        approvers=("reference-approver",),
        key_id="reference-key",
        issued_at=_EPOCH,
        valid_from=_EPOCH,
        valid_until=datetime(2026, 1, 2, tzinfo=UTC),
        phase1=Phase1Grants(defense_profiles=frozenset({"object-ownership"})),
        phase2=Phase2Grants(
            ownership_seed=1,
            ownership=(OwnershipScope(tenant_id="org-a", resource_ids=frozenset({"ticket-1"})),),
            database_credential_handle="reference-database",
            containment_prefix="reference",
        ),
        phase3=Phase3Grants(
            model_credential_handle="reference-model",
            model_pins=(
                ModelPin(
                    pin_id="reference-pin",
                    provider="offline",
                    model_id="reference-model",
                    model_version="reference-v1",
                    decoding=DecodingParameters(seed=1),
                    system_prompt_hash=_DIGEST,
                ),
            ),
            token_budget=1,
            cost_microusd_budget=1,
        ),
        phase4=phase4,
        assets=(
            AssetScope(
                asset_id="reference-asset",
                scheme="http",
                host="127.0.0.1",
                port=28080,
                tenant_ids=frozenset({"org-a"}),
                allowed_resolved_addresses=frozenset({IPv4Address("127.0.0.1")}),
            ),
        ),
        allowed_adapters=frozenset({"http"}),
        allowed_operations=frozenset({"ticket.read"}),
        allowed_side_effects=frozenset({SideEffectClass.READ}),
        credential_handles=frozenset({"reference-actor"}),
        credential_scopes={"reference-actor": frozenset({"ticket.read"})},
        budgets=BudgetLimits(requests=1, records=1),
        signature="",
    )


def _reference_scenario() -> Phase1Scenario:
    step = Step(
        schema_version="1.3.0",
        node_id="reference-step",
        adapter="agent",
        operation="agent.ask",
        asset_id="reference-asset",
        target_tenant="org-a",
        arguments={"task": "reference"},
    )
    oracle = OracleSpec(
        schema_version="1.3.0", operator="count", path=("emails",), expected=0, comparison="eq"
    )
    return Phase1Scenario(
        schema_version="1.3.0",
        scenario_id="schema-reference",
        surface="agent",
        risk_class="prompt-injection",
        injection_channel="ticket",
        fixture_seed=1,
        actor=Actor(
            schema_version="1.3.0",
            actor_id="reference-actor",
            role="agent",
            tenant_id="org-a",
            credential_handle="reference-actor",
        ),
        legitimate_objective="reference",
        attacker_objective="reference",
        agent_task=AgentTask(objective="reference", capabilities=frozenset({"email.send"})),
        capabilities=frozenset({"agent.ask"}),
        clean_steps=(step,),
        attack_steps=(step.model_copy(update={"node_id": "reference-attack"}),),
        security_oracle=oracle,
        utility_oracle=oracle,
        expected_telemetry=("reference-rule",),
        defense_profile="object-ownership",
        taxonomy_mappings={"owasp-llm-2025": ("LLM01",)},
    )


def _reference_summary() -> RunSummary:
    oracle = OracleResult(
        schema_version="1.3.0",
        verdict="true",
        oracle_version="state-v1",
        evidence_ids=("reference-evidence",),
    )
    leg = LegResult(
        schema_version="1.3.0",
        seed_hash=_DIGEST,
        utility=oracle,
        security=oracle,
        susceptible=True,
        unauthorized_side_effects=0,
        detectors=(
            DetectorResult(
                schema_version="1.3.0",
                rule_id="reference-rule",
                expected=True,
                observed=True,
                evidence_ids=("reference-evidence",),
                time_to_detect=1,
            ),
        ),
    )
    return RunSummary(
        schema_version="1.3.0",
        run_id="reference-run",
        scenario_id="schema-reference",
        status="passed",
        reason="REFERENCE",
        manifest_digest=_DIGEST,
        scenario_digest=_DIGEST,
        baseline=leg,
        replay=leg,
        findings=(
            Finding(
                schema_version="1.3.0",
                finding_id="reference-finding",
                scenario_id="schema-reference",
                asset_id="reference-asset",
                attacker_goal="reference",
                observed_impact="reference",
                evidence_ids=("reference-evidence",),
                oracle_version="state-v1",
                manifest_digest=_DIGEST,
                scenario_digest=_DIGEST,
                seed_hash=_DIGEST,
                reproducible=False,
                severity_rationale="reference",
                taxonomy_mappings={"owasp-llm-2025": ("LLM01",)},
                status="confirmed",
                mitigation="object-ownership",
            ),
        ),
    )


def _reference_attestation() -> RunAttestation:
    return RunAttestation(
        subject_digest=_DIGEST,
        subject_kind="run-bundle",
        builder="schema-reference",
        key_provenance="provided",
        created_at=_EPOCH,
        materials=AttestationMaterials(
            code_commit=_COMMIT,
            lockfile_digest=_DIGEST,
            corpus_digest=_DIGEST,
            manifest_digest=_DIGEST,
            scenario_digests=(_DIGEST,),
            model_pin_ids=("reference-pin",),
        ),
        byproducts={"tests": 1},
        key_id="reference-key",
        signature="",
    )


def _reference_event() -> EvidenceEvent:
    return EvidenceEvent(
        schema_version="1.1.0",
        scenario_id="schema-reference",
        scenario_version="1.0.0",
        stage="attack",
        component_version="runtime-v1",
        run_id="reference-run",
        trace_id="reference-trace",
        sequence=1,
        timestamp=_EPOCH,
        actor="safety-kernel",
        kind=EventKind.POLICY,
        manifest_digest=_DIGEST,
        policy_digest=_DIGEST,
        action_digest=_DIGEST,
        decision="permit",
        reason_code="PERMITTED",
        parent_hash=_DIGEST,
    )


def schema_digests() -> dict[str, str]:
    """Canonical digests of frozen reference documents, built entirely from constants.

    Additive schema changes (a new optional field defaulting to ``None``) do not move these,
    which is exactly right: the gate catches breaking canonical-surface drift, and an intended
    break ships with a version bump and a baseline-bump commit in the same change.
    """
    return {
        "authorization-manifest-1.3": _reference_manifest("1.3.0").manifest_digest(),
        "authorization-manifest-1.4": _reference_manifest("1.4.0").manifest_digest(),
        "scenario-1.3": _reference_scenario().digest(),
        "run-summary-1.3": _reference_summary().digest(),
        "run-attestation-1.0": _reference_attestation().attestation_digest(),
        "evidence-event-1.1": _reference_event().digest(exclude={"event_hash"}),
    }


def all_gates(
    *,
    events: Sequence[EvidenceEvent],
    limits: BudgetLimits,
    summaries: Sequence[RunSummary],
    registry: RegressionRegistry,
    outcomes: Mapping[str, bool],
    schema_baseline: Mapping[str, str],
    risk_baseline: RiskClassBaseline,
    risk_current: Sequence[RiskClassMetrics],
) -> tuple[GateDecision, ...]:
    """All five gates over prepared inputs. Summaries carrying verdicts are checked binding."""
    for summary in summaries:
        require_binding(*summary.findings)
        if summary.baseline is not None:
            require_binding(summary.baseline.security, summary.baseline.utility)
        if summary.replay is not None:
            require_binding(summary.replay.security, summary.replay.utility)
    return (
        scope_gate(events),
        critical_regression_gate(registry, outcomes),
        schema_drift_gate(schema_baseline, schema_digests()),
        budget_gate(events, limits, summaries),
        risk_class_gate(risk_baseline, risk_current),
    )
