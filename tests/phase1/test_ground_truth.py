"""Ground-truth scoring: recall and false positives come from explicit labels."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from purpleloop.runtime.demo import ROOT
from purpleloop.schemas.phase1 import (
    Finding,
    GroundTruth,
    LegResult,
    OracleResult,
    RunSummary,
    load_ground_truth,
    load_scenario,
)
from purpleloop.scoring.phase1 import corpus_metrics

GROUND_TRUTH = ROOT / "scenarios/phase1/ground-truth.json"


def make_finding(scenario_id: str) -> Finding:
    return Finding(
        finding_id=f"{scenario_id}-1",
        scenario_id=scenario_id,
        asset_id="record-b",
        attacker_goal="read another tenant's object",
        observed_impact="cross-tenant record disclosed",
        evidence_ids=("event-1",),
        oracle_version="oracle-v1",
        manifest_digest="0" * 64,
        scenario_digest="1" * 64,
        seed_hash="2" * 64,
        reproducible=True,
        severity_rationale="synthetic cross-tenant disclosure",
        taxonomy_mappings={"owasp": ("API1:2023",)},
        status="confirmed",
        mitigation="enforce tenant ownership",
    )


def make_leg(verdict: str) -> LegResult:
    oracle = OracleResult(verdict=verdict, oracle_version="oracle-v1")  # type: ignore[arg-type]
    return LegResult(
        seed_hash="2" * 64,
        utility=OracleResult(verdict="true", oracle_version="oracle-v1"),
        security=oracle,
        susceptible=verdict == "true",
        unauthorized_side_effects=0,
        detectors=(),
    )


def make_summary(
    scenario_id: str,
    *,
    findings: int = 1,
    replay_verdict: str | None = "false",
) -> RunSummary:
    return RunSummary(
        run_id=f"run-{scenario_id}",
        scenario_id=scenario_id,
        status="passed",
        reason="synthetic",
        manifest_digest="0" * 64,
        scenario_digest="1" * 64,
        baseline=make_leg("true"),
        replay=None if replay_verdict is None else make_leg(replay_verdict),
        findings=tuple(make_finding(scenario_id) for _ in range(findings)),
    )


@pytest.fixture
def truth() -> GroundTruth:
    return load_ground_truth(GROUND_TRUTH)


def test_labels_cover_the_corpus_exactly(truth: GroundTruth) -> None:
    corpus = {
        load_scenario(path).scenario_id
        for path in sorted((ROOT / "scenarios/phase1").glob("*.yaml"))
    }
    assert {case.scenario_id for case in truth.cases} == corpus
    assert len(corpus) == 5


def test_perfect_corpus_scores_full_recall_without_false_positives(truth: GroundTruth) -> None:
    metrics = corpus_metrics(truth, [make_summary(c.scenario_id) for c in truth.cases])
    assert metrics["seeded_recall"] == 1.0
    assert metrics["seeded_true_positives"] == 5 and metrics["seeded_false_negatives"] == 0
    assert metrics["false_positives"] == 0 and metrics["false_positive_rate"] == 0.0
    assert metrics["true_negatives"] == 5
    assert metrics["unevaluated_scenarios"] == []


def test_missed_seeded_finding_lowers_recall(truth: GroundTruth) -> None:
    summaries = [make_summary(c.scenario_id) for c in truth.cases]
    summaries[0] = make_summary(truth.cases[0].scenario_id, findings=0)
    metrics = corpus_metrics(truth, summaries)
    assert metrics["seeded_false_negatives"] == 1
    assert metrics["seeded_recall"] == pytest.approx(0.8)


def test_finding_in_defended_negative_control_is_a_false_positive(truth: GroundTruth) -> None:
    summaries = [make_summary(c.scenario_id) for c in truth.cases]
    summaries[0] = make_summary(truth.cases[0].scenario_id, replay_verdict="true")
    metrics = corpus_metrics(truth, summaries)
    assert metrics["false_positives"] == 1
    assert metrics["false_positive_rate"] == pytest.approx(0.2)
    assert metrics["true_negatives"] == 4


def test_unlabelled_scenario_raises_instead_of_being_skipped(truth: GroundTruth) -> None:
    with pytest.raises(KeyError):
        corpus_metrics(truth, [make_summary("not-in-ground-truth")])


def test_unevaluated_and_missing_controls_are_reported(truth: GroundTruth) -> None:
    metrics = corpus_metrics(truth, [make_summary(truth.cases[0].scenario_id, replay_verdict=None)])
    assert metrics["missing_negative_controls"] == [f"run-{truth.cases[0].scenario_id}"]
    assert metrics["negative_control_runs"] == 0 and metrics["false_positive_rate"] == 0.0
    assert metrics["unevaluated_scenarios"] == sorted(c.scenario_id for c in truth.cases[1:])


def test_empty_and_duplicate_ground_truth_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(ValidationError):
        GroundTruth(cases=())
    case: dict[str, Any] = {
        "scenario_id": "bola",
        "positive_control": "baseline",
        "expected_findings": 1,
        "negative_control": "defended-replay",
        "expected_negative_findings": 0,
    }
    with pytest.raises(ValidationError):
        GroundTruth.model_validate({"cases": [case, case]})
    path = tmp_path / "gt.json"
    path.write_text("[]")
    with pytest.raises(ValueError, match="must be an object"):
        load_ground_truth(path)
