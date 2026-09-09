"""Phase 2 metrics. Each ships with a test that fails when the metric is faked."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from purpleloop.control.lanes import LaneContract
from purpleloop.schemas.event import EventKind, EvidenceEvent
from purpleloop.schemas.phase1 import ExecutionPlan, Phase1Scenario, RunSummary
from purpleloop.schemas.phase2 import EvidenceCompleteness, ResourceReport, ResourceUsage

TOLERANCE_PERCENT = 10.0

# Every event must carry these; values may not be None or empty.
REQUIRED_EVENT_FIELDS: tuple[str, ...] = (
    "schema_version",
    "scenario_id",
    "scenario_version",
    "stage",
    "component_version",
    "run_id",
    "trace_id",
    "sequence",
    "timestamp",
    "actor",
    "kind",
    "manifest_digest",
    "policy_digest",
    "event_hash",
)
# Per-kind fields. A dotted name reaches into ``data``.
KIND_FIELDS: dict[EventKind, tuple[str, ...]] = {
    EventKind.ADMISSION: ("action_digest", "decision", "reason_code"),
    EventKind.POLICY: ("action_digest", "decision", "reason_code"),
    EventKind.BUDGET: ("action_digest", "decision", "reason_code"),
    EventKind.RESULT: ("action_digest", "decision", "reason_code"),
    EventKind.ADAPTER: ("action_digest", "reason_code"),
    EventKind.LIFECYCLE: ("reason_code",),
    EventKind.ORACLE: ("reason_code", "data.utility", "data.security"),
    EventKind.DETECTOR: ("reason_code", "data.results"),
    EventKind.DEFENSE: ("reason_code", "data.profile", "data.verified"),
    EventKind.TERMINATION: ("reason_code", "data.status", "data.teardown_complete"),
    EventKind.MODEL: ("reason_code", "data.call", "data.retrieved", "data.quarantined"),
    EventKind.JUDGE: ("reason_code", "data.verdict", "data.provenance", "data.rubric_id"),
    EventKind.PROPOSAL: ("reason_code", "data.accepted", "data.operation"),
}


#: Per-reason overrides. An ORACLE event is emitted for two different things: the paired scoring,
#: which decides both utility and security, and the utility-under-attack pass, which decides only
#: utility. Requiring a security field on the second would either fail honestly or invite a null
#: placeholder, and a placeholder is exactly how a completeness metric becomes decorative.
REASON_FIELDS: dict[tuple[EventKind, str], tuple[str, ...]] = {
    (EventKind.ORACLE, "UTILITY_UNDER_ATTACK"): ("reason_code", "data.utility"),
}


def required_fields(event: EvidenceEvent) -> tuple[str, ...]:
    override = REASON_FIELDS.get((event.kind, event.reason_code or ""))
    return override if override is not None else KIND_FIELDS.get(event.kind, ())


def _present(event: EvidenceEvent, name: str) -> bool:
    if name.startswith("data."):
        value: Any = event.data
        for part in name.split(".")[1:]:
            if not isinstance(value, dict) or part not in value:
                return False
            value = value[part]
        return value is not None
    value = getattr(event, name)
    return value is not None and value != ""


def evidence_completeness(events: Sequence[EvidenceEvent]) -> EvidenceCompleteness:
    """Fraction of required evidence fields that are present across a run's ledger.

    Computed field by field, never by inspection. ``parent_hash`` is required on every event
    after the first, and kind-specific fields are required on the kinds that define them.
    """
    required = 0
    present = 0
    missing: list[str] = []
    for event in events:
        names = list(REQUIRED_EVENT_FIELDS) + list(required_fields(event))
        if event.sequence > 0:
            names.append("parent_hash")
        for name in names:
            required += 1
            if _present(event, name):
                present += 1
            else:
                missing.append(f"{event.sequence}:{name}")
    return EvidenceCompleteness(
        required_fields=required,
        present_fields=present,
        completeness=present / required if required else 0.0,
        missing=tuple(missing),
    )


def estimate_resources(plan: ExecutionPlan, lane: LaneContract) -> ResourceUsage:
    """Pre-run estimate from the compiled plan and the lane's fixed lifecycle shape.

    Requests and records follow the reserved budgets of every node across both paired legs plus
    the control-plane calls the lifecycle always makes. Wall time uses the lane's calibration
    constants; it is an estimate to be measured against, not a target to be met.
    """
    leg_requests = sum(node.action.budget.requests for node in plan.nodes)
    leg_records = sum(node.action.budget.records for node in plan.nodes)
    browser_nodes = sum(node.action.adapter == "browser" for node in plan.nodes)
    requests = 2 * leg_requests + lane.control_calls_per_run
    records = 2 * leg_records + lane.control_calls_per_run
    contexts = 2 * browser_nodes
    wall = (
        lane.calibration.fixed_seconds
        + requests * lane.calibration.seconds_per_request
        + contexts * lane.calibration.seconds_per_browser_context
    )
    return ResourceUsage(
        requests=requests,
        records=records,
        browser_contexts=contexts,
        wall_time_seconds=round(wall, 6),
    )


def resource_report(estimated: ResourceUsage, actual: ResourceUsage) -> ResourceReport:
    delta: dict[str, float] = {}
    within: dict[str, bool] = {}
    for name in ResourceUsage.model_fields:
        expected = float(getattr(estimated, name))
        observed = float(getattr(actual, name))
        if expected == 0:
            percent = 0.0 if observed == 0 else 100.0
        else:
            percent = round((observed - expected) / expected * 100.0, 3)
        delta[name] = percent
        within[name] = abs(percent) <= TOLERANCE_PERCENT
    return ResourceReport(
        estimated=estimated, actual=actual, delta_percent=delta, within_tolerance=within
    )


def cross_surface_agreement(
    scenarios: Sequence[Phase1Scenario], summaries: Sequence[RunSummary]
) -> dict[str, Any]:
    """Compare oracle verdicts across surfaces that share one oracle specification.

    Disagreements are listed per group, never averaged into a rate. A group with a single
    surface is reported as unpaired rather than counted as agreeing.
    """
    by_scenario = {scenario.scenario_id: scenario for scenario in scenarios}
    groups: dict[str, list[dict[str, Any]]] = {}
    for summary in summaries:
        scenario = by_scenario.get(summary.scenario_id)
        if scenario is None or scenario.shared_oracle is None:
            continue
        groups.setdefault(scenario.shared_oracle, []).append(
            {
                "scenario_id": summary.scenario_id,
                "surface": scenario.effective_surface,
                "baseline": summary.baseline.security.verdict if summary.baseline else None,
                "replay": summary.replay.security.verdict if summary.replay else None,
            }
        )
    report: list[dict[str, Any]] = []
    disagreements: list[str] = []
    unpaired: list[str] = []
    for name in sorted(groups):
        members = sorted(groups[name], key=lambda item: str(item["scenario_id"]))
        surfaces = {member["surface"] for member in members}
        if len(surfaces) < 2:
            unpaired.append(name)
            status = "unpaired"
        else:
            agreed = (
                len({member["baseline"] for member in members}) == 1
                and len({member["replay"] for member in members}) == 1
            )
            status = "agree" if agreed else "disagree"
            if not agreed:
                disagreements.append(name)
        report.append({"oracle": name, "status": status, "members": members})
    return {
        "groups": report,
        "paired_groups": len(report) - len(unpaired),
        "agreed_groups": sum(group["status"] == "agree" for group in report),
        "disagreements": disagreements,
        "unpaired": unpaired,
    }


def replay_rate(fingerprints: Sequence[tuple[str | None, str | None]]) -> dict[str, Any]:
    """Share of trials whose normalized event and oracle hashes equal the first trial's.

    Every trial is counted; a mismatch is listed with its index rather than excluded.
    """
    if not fingerprints:
        return {"trials": 0, "matches": 0, "rate": 0.0, "mismatches": []}
    reference = fingerprints[0]
    mismatches = [index for index, item in enumerate(fingerprints) if item != reference]
    return {
        "trials": len(fingerprints),
        "matches": len(fingerprints) - len(mismatches),
        "rate": (len(fingerprints) - len(mismatches)) / len(fingerprints),
        "mismatches": mismatches,
    }
