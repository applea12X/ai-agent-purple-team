"""Per-risk-class corpus metrics: the input to the risk-class regression gate.

This metric ships with tests that fail when it is faked, following the ``corpus_metrics``
reference. A missed seeded finding must lower that class's true positives and nothing else's,
a finding in a defended negative control must count as a false positive, an unlabelled
scenario must raise, and advisory input must be refused before any counting happens.
"""

from __future__ import annotations

import pytest

from purpleloop.schemas.phase1 import (
    Actor,
    AgentTask,
    DetectorResult,
    Finding,
    GroundTruth,
    LegResult,
    OracleResult,
    OracleSpec,
    Phase1Scenario,
    RunSummary,
    Step,
)
from purpleloop.schemas.phase3 import AdvisoryVerdictError
from purpleloop.scoring.phase4 import UNCLASSIFIED, risk_class_metrics

DIGEST = "a" * 64


def scenario(scenario_id: str, risk_class: str | None) -> Phase1Scenario:
    step = Step(
        schema_version="1.3.0",
        node_id="ask",
        adapter="agent",
        operation="agent.ask",
        asset_id="supportlab-data",
        target_tenant="org-a",
        arguments={"task": "t"},
    )
    oracle = OracleSpec(schema_version="1.3.0", operator="count", path=("emails",), expected=0)
    return Phase1Scenario(
        schema_version="1.3.0",
        scenario_id=scenario_id,
        surface="agent",
        risk_class=risk_class,  # type: ignore[arg-type]
        injection_channel="ticket",
        fixture_seed=1,
        actor=Actor(
            schema_version="1.3.0",
            actor_id="agent-a",
            role="agent",
            tenant_id="org-a",
            credential_handle="supportlab-agent-a",
        ),
        legitimate_objective="o",
        attacker_objective="o",
        agent_task=AgentTask(objective="o", capabilities=frozenset({"email.send"})),
        capabilities=frozenset({"agent.ask"}),
        clean_steps=(step,),
        attack_steps=(step.model_copy(update={"node_id": "attack"}),),
        security_oracle=oracle,
        utility_oracle=oracle,
        expected_telemetry=("r",),
        defense_profile="capability-scoping",
        taxonomy_mappings={"OWASP-LLM-2025": ("LLM01",)},
    )


def oracle(verdict: str, provenance: str = "deterministic") -> OracleResult:
    return OracleResult(
        verdict=verdict,  # type: ignore[arg-type]
        provenance=provenance,  # type: ignore[arg-type]
        oracle_version="state-v1",
        evidence_ids=("e",),
    )


def finding(scenario_id: str, provenance: str = "deterministic") -> Finding:
    return Finding(
        provenance=provenance,  # type: ignore[arg-type]
        finding_id=f"{scenario_id}-finding",
        scenario_id=scenario_id,
        asset_id="supportlab-data",
        attacker_goal="g",
        observed_impact="i",
        evidence_ids=("e",),
        oracle_version="state-v1",
        manifest_digest=DIGEST,
        scenario_digest=DIGEST,
        seed_hash=DIGEST,
        reproducible=False,
        severity_rationale="synthetic",
        taxonomy_mappings={"OWASP-LLM-2025": ("LLM01",)},
        status="confirmed",
        mitigation="capability-scoping",
    )


def summary(
    scenario_id: str,
    *,
    found: bool = True,
    replay_security: str = "false",
    replay_side_effects: int = 0,
    with_replay: bool = True,
    finding_provenance: str = "deterministic",
) -> RunSummary:
    leg = LegResult(
        seed_hash=DIGEST,
        utility=oracle("true"),
        security=oracle("true"),
        susceptible=True,
        unauthorized_side_effects=1,
        detectors=(DetectorResult(rule_id="r", expected=True, observed=True, evidence_ids=("e",)),),
    )
    replay = leg.model_copy(
        update={
            "security": oracle(replay_security),
            "unauthorized_side_effects": replay_side_effects,
        }
    )
    return RunSummary(
        run_id=f"{scenario_id}-run",
        scenario_id=scenario_id,
        status="passed",
        reason="TEST",
        manifest_digest=DIGEST,
        scenario_digest=DIGEST,
        baseline=leg,
        replay=replay if with_replay else None,
        findings=(finding(scenario_id, finding_provenance),) if found else (),
    )


SCENARIOS = [
    scenario("inject-1", "prompt-injection"),
    scenario("inject-2", "prompt-injection"),
    scenario("exfil-1", "canary-exfiltration"),
    scenario("legacy-1", None),
]

TRUTH = GroundTruth.model_validate(
    {
        "cases": [
            {
                "scenario_id": scenario_id,
                "positive_control": "baseline",
                "expected_findings": 1,
                "negative_control": "defended-replay",
                "expected_negative_findings": 0,
            }
            for scenario_id in ("inject-1", "inject-2", "exfil-1", "legacy-1")
        ]
    }
)


def by_class(summaries: list[RunSummary]) -> dict[str, object]:
    return {entry.risk_class: entry for entry in risk_class_metrics(SCENARIOS, TRUTH, summaries)}


def clean() -> list[RunSummary]:
    return [summary("inject-1"), summary("inject-2"), summary("exfil-1"), summary("legacy-1")]


def test_a_clean_corpus_groups_by_declared_risk_class() -> None:
    metrics = by_class(clean())
    assert set(metrics) == {"prompt-injection", "canary-exfiltration", UNCLASSIFIED}
    injection = metrics["prompt-injection"]
    assert injection.scenarios == 2  # type: ignore[attr-defined]
    assert injection.seeded_true_positives == 2  # type: ignore[attr-defined]
    assert injection.seeded_false_negatives == 0  # type: ignore[attr-defined]
    assert injection.negative_controls == 2  # type: ignore[attr-defined]
    assert injection.recall == 1.0  # type: ignore[attr-defined]


def test_a_missed_finding_lowers_only_its_own_class() -> None:
    """Faking this metric (e.g. counting scenarios instead of findings) fails here."""
    summaries = clean()
    summaries[0] = summary("inject-1", found=False)
    metrics = by_class(summaries)
    injection = metrics["prompt-injection"]
    assert injection.seeded_true_positives == 1  # type: ignore[attr-defined]
    assert injection.seeded_false_negatives == 1  # type: ignore[attr-defined]
    assert injection.recall == 0.5  # type: ignore[attr-defined]
    exfil = metrics["canary-exfiltration"]
    assert exfil.seeded_false_negatives == 0  # type: ignore[attr-defined]


def test_a_finding_in_a_defended_negative_control_is_a_false_positive() -> None:
    summaries = clean()
    summaries[2] = summary("exfil-1", replay_security="true", replay_side_effects=2)
    exfil = by_class(summaries)["canary-exfiltration"]
    assert exfil.false_positives == 1  # type: ignore[attr-defined]
    assert exfil.defended_unauthorized_side_effects == 2  # type: ignore[attr-defined]


def test_a_missing_negative_control_is_not_counted_as_one() -> None:
    summaries = clean()
    summaries[1] = summary("inject-2", with_replay=False)
    injection = by_class(summaries)["prompt-injection"]
    assert injection.scenarios == 2  # type: ignore[attr-defined]
    assert injection.negative_controls == 1  # type: ignore[attr-defined]


def test_an_unlabelled_scenario_raises_rather_than_being_skipped() -> None:
    with pytest.raises(KeyError, match="unlabelled scenario"):
        risk_class_metrics(SCENARIOS, TRUTH, [*clean(), summary("not-labelled")])


def test_advisory_findings_are_refused_before_counting() -> None:
    summaries = clean()
    summaries[0] = summary("inject-1", finding_provenance="advisory")
    with pytest.raises(AdvisoryVerdictError):
        risk_class_metrics(SCENARIOS, TRUTH, summaries)
