from __future__ import annotations

from collections.abc import Sequence
from typing import Any, Literal

from purpleloop.schemas.common import digest_data
from purpleloop.schemas.phase1 import (
    DetectorResult,
    GroundTruth,
    OracleResult,
    OracleSpec,
    RunSummary,
)

MISSING = object()


def at_path(value: Any, path: tuple[str | int, ...]) -> Any:
    for part in path:
        if isinstance(value, dict) and isinstance(part, str):
            value = value.get(part, MISSING)
        elif isinstance(value, list) and isinstance(part, int) and 0 <= part < len(value):
            value = value[part]
        else:
            return MISSING
    return value


def evaluate(
    spec: OracleSpec,
    *,
    before: dict[str, Any],
    state: dict[str, Any],
    responses: list[dict[str, Any]],
    telemetry: list[dict[str, Any]],
    evidence_ids: tuple[str, ...],
) -> OracleResult:
    sources = {"state": state, "responses": responses, "telemetry": telemetry}
    observed = at_path(sources[spec.source], spec.path)
    verdict: Literal["true", "false", "inconclusive"] = "false"
    if spec.operator == "exists":
        verdict = "true" if observed is not MISSING else "false"
    elif observed is not MISSING:
        if spec.operator == "equals":
            verdict = "true" if observed == spec.expected else "false"
        elif spec.operator == "contains":
            if not isinstance(observed, (str, list, dict)):
                verdict = "inconclusive"
            else:
                try:
                    verdict = "true" if spec.expected in observed else "false"
                except TypeError:
                    verdict = "inconclusive"
        elif spec.operator == "count":
            if not isinstance(observed, (list, dict, str)) or not isinstance(spec.expected, int):
                verdict = "inconclusive"
            else:
                count = len(observed)
                matches = {
                    "eq": count == spec.expected,
                    "gt": count > spec.expected,
                    "ge": count >= spec.expected,
                    "lt": count < spec.expected,
                    "le": count <= spec.expected,
                }
                verdict = "true" if matches[spec.comparison] else "false"
        elif spec.operator == "delta":
            previous = at_path(before, spec.path)
            verdict = (
                "true"
                if previous is MISSING or digest_data(previous) != digest_data(observed)
                else "false"
            )
    return OracleResult(
        verdict=verdict,
        observed=None if observed is MISSING else observed,
        oracle_version=spec.oracle_version,
        evidence_ids=evidence_ids,
    )


def detect(
    events: list[dict[str, Any]],
    expected: tuple[str, ...],
    evidence_id: str,
    first_attack_tick: int,
) -> tuple[DetectorResult, ...]:
    rules = sorted(
        set(expected) | {str(event["rule_id"]) for event in events if event.get("rule_id")}
    )
    results = []
    for rule in rules:
        matched = [e for e in events if e.get("rule_id") == rule]
        results.append(
            DetectorResult(
                rule_id=rule,
                expected=rule in expected,
                observed=bool(matched),
                evidence_ids=(evidence_id,) if matched else (),
                time_to_detect=min(int(e["tick"]) for e in matched) - first_attack_tick
                if matched
                else None,
            )
        )
    return tuple(results)


def detection_metrics(results: tuple[DetectorResult, ...]) -> dict[str, float | int]:
    tp = sum(r.expected and r.observed for r in results)
    fp = sum(not r.expected and r.observed for r in results)
    fn = sum(r.expected and not r.observed for r in results)
    return {
        "true_positives": tp,
        "false_positives": fp,
        "false_negatives": fn,
        "precision": tp / (tp + fp) if tp + fp else 1.0,
        "recall": tp / (tp + fn) if tp + fn else 1.0,
    }


def corpus_metrics(truth: GroundTruth, summaries: Sequence[RunSummary]) -> dict[str, Any]:
    """Score a corpus against explicit ground-truth labels.

    Recall and false positives come from labelled positive and negative controls, never from
    scenario-level pass/fail. An unlabelled scenario raises rather than being skipped, and
    labelled scenarios that were never executed are reported instead of ignored.
    """
    tp = fn = fp = tn = 0
    positive_runs = negative_runs = 0
    missing_negative_controls: list[str] = []
    for summary in summaries:
        case = truth.case(summary.scenario_id)
        positive_runs += 1
        observed = len(summary.findings)
        tp += min(observed, case.expected_findings)
        fn += max(case.expected_findings - observed, 0)
        if summary.replay is None:
            missing_negative_controls.append(summary.run_id)
            continue
        negative_runs += 1
        negative_findings = int(summary.replay.security.verdict == "true")
        extra = max(negative_findings - case.expected_negative_findings, 0)
        fp += extra
        tn += not extra
    evaluated = {summary.scenario_id for summary in summaries}
    return {
        "seeded_true_positives": tp,
        "seeded_false_negatives": fn,
        "seeded_recall": tp / (tp + fn) if tp + fn else 0.0,
        "false_positives": fp,
        "true_negatives": tn,
        "false_positive_rate": fp / negative_runs if negative_runs else 0.0,
        "positive_control_runs": positive_runs,
        "negative_control_runs": negative_runs,
        "missing_negative_controls": missing_negative_controls,
        "unevaluated_scenarios": sorted(
            case.scenario_id for case in truth.cases if case.scenario_id not in evaluated
        ),
    }
