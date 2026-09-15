"""The five gate decision functions, both sides of every threshold (ADR 0013).

CI calls exactly these functions, so these tests are the proof of the gate logic; the red
branches prove the wiring. The gate-isolation cases extend the Phase 3 rule to every new gate:
an advisory verdict in a gate's input path is rejected at the type boundary, never averaged in.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from purpleloop.reporting.gates import (
    all_gates,
    budget_gate,
    critical_regression_gate,
    outcomes_from_junit,
    risk_class_gate,
    schema_digests,
    schema_drift_gate,
    scope_gate,
)
from purpleloop.runtime.demo import ROOT
from purpleloop.schemas.authorization import BudgetLimits
from purpleloop.schemas.event import EventKind, EvidenceEvent
from purpleloop.schemas.phase1 import (
    DetectorResult,
    Finding,
    LegResult,
    OracleResult,
    RunSummary,
)
from purpleloop.schemas.phase3 import AdvisoryVerdictError
from purpleloop.schemas.phase4 import (
    RegressionEntry,
    RegressionRegistry,
    RiskClassBaseline,
    RiskClassMetrics,
)
from purpleloop.scoring.phase4 import compare_risk_classes, fisher_exact_two_sided

DIGEST_A = "a" * 64
DIGEST_B = "b" * 64


def event(
    sequence: int,
    kind: EventKind,
    decision: str,
    action_digest: str = DIGEST_A,
) -> EvidenceEvent:
    return EvidenceEvent(
        run_id="gate-test",
        trace_id="gate-test",
        sequence=sequence,
        timestamp=datetime(2026, 1, 1, tzinfo=UTC),
        actor="safety-kernel",
        kind=kind,
        manifest_digest=DIGEST_A,
        policy_digest=DIGEST_A,
        action_digest=action_digest,
        decision=decision,
        reason_code="TEST",
    )


def oracle(verdict: str, provenance: str = "deterministic") -> OracleResult:
    return OracleResult(
        verdict=verdict,  # type: ignore[arg-type]
        provenance=provenance,  # type: ignore[arg-type]
        oracle_version="state-v1",
        evidence_ids=("e",),
    )


def summary(*, findings_provenance: str = "deterministic", requests: int = 1) -> RunSummary:
    leg = LegResult(
        seed_hash=DIGEST_A,
        utility=oracle("true"),
        security=oracle("true"),
        susceptible=True,
        unauthorized_side_effects=0,
        detectors=(DetectorResult(rule_id="r", expected=True, observed=True, evidence_ids=("e",)),),
    )
    finding = Finding(
        provenance=findings_provenance,  # type: ignore[arg-type]
        finding_id="f-1",
        scenario_id="s-1",
        asset_id="a",
        attacker_goal="g",
        observed_impact="i",
        evidence_ids=("e",),
        oracle_version="state-v1",
        manifest_digest=DIGEST_A,
        scenario_digest=DIGEST_A,
        seed_hash=DIGEST_A,
        reproducible=False,
        severity_rationale="synthetic",
        taxonomy_mappings={"owasp-llm-2025": ("LLM01",)},
        status="confirmed",
        mitigation="m",
    )
    return RunSummary(
        run_id="run-1",
        scenario_id="s-1",
        status="passed",
        reason="TEST",
        manifest_digest=DIGEST_A,
        scenario_digest=DIGEST_A,
        baseline=leg,
        replay=leg.model_copy(update={"security": oracle("false")}),
        findings=(finding,),
        budget_used=summary_budget(requests),
    )


def summary_budget(requests: int) -> object:
    from purpleloop.schemas.action import BudgetRequest

    return BudgetRequest(requests=requests, records=1)


LIMITS = BudgetLimits(requests=10, records=10)


# --- scope gate -------------------------------------------------------------------------------


def test_scope_gate_passes_a_permitted_execution() -> None:
    events = [event(1, EventKind.POLICY, "permit"), event(2, EventKind.RESULT, "permit")]
    decision = scope_gate(events)
    assert not decision.blocked and decision.reason_code == "NO_BYPASS_OBSERVED"


def test_scope_gate_blocks_an_execution_without_a_permit() -> None:
    decision = scope_gate([event(2, EventKind.RESULT, "permit")])
    assert decision.blocked and decision.reason_code == "SCOPE_BYPASS"
    assert "without a policy permit" in decision.detail


def test_scope_gate_blocks_an_execution_after_a_standing_denial() -> None:
    events = [
        event(1, EventKind.POLICY, "permit"),
        event(2, EventKind.POLICY, "deny"),
        event(3, EventKind.RESULT, "permit"),
    ]
    decision = scope_gate(events)
    assert decision.blocked and "standing denial" in decision.detail


def test_scope_gate_treats_an_empty_ledger_as_blocking() -> None:
    """'The gate saw no evidence' and 'the evidence was clean' are different facts."""
    decision = scope_gate([])
    assert decision.blocked and decision.reason_code == "NO_EVIDENCE"


def test_scope_gate_ignores_denied_actions_that_never_executed() -> None:
    events = [
        event(1, EventKind.POLICY, "deny", DIGEST_B),
        event(2, EventKind.POLICY, "permit"),
        event(3, EventKind.RESULT, "permit"),
    ]
    assert not scope_gate(events).blocked


# --- budget gate ------------------------------------------------------------------------------


def test_budget_gate_passes_use_within_limits() -> None:
    decision = budget_gate([], LIMITS, [summary()])
    assert not decision.blocked and decision.reason_code == "BUDGETS_HELD"


def test_budget_gate_blocks_arithmetic_over_the_signed_limit() -> None:
    decision = budget_gate([], LIMITS, [summary(requests=LIMITS.requests + 1)])
    assert decision.blocked and "over signed limit" in decision.detail


def test_budget_gate_blocks_an_execution_after_a_budget_denial() -> None:
    events = [
        event(1, EventKind.POLICY, "permit"),
        event(2, EventKind.BUDGET, "deny"),
        event(3, EventKind.RESULT, "permit"),
    ]
    decision = budget_gate(events, LIMITS, [summary()])
    assert decision.blocked and "after a budget denial" in decision.detail


def test_budget_gate_accepts_a_denial_that_stopped_the_run() -> None:
    """A recorded budget stop is correct behaviour, not a violation."""
    events = [event(1, EventKind.POLICY, "permit"), event(2, EventKind.BUDGET, "deny")]
    assert not budget_gate(events, LIMITS, [summary()]).blocked


# --- critical-regression gate -----------------------------------------------------------------

REGISTRY = RegressionRegistry(
    entries=(
        RegressionEntry(
            finding_class="bola", scenario_id="bola", status="covered", test="tests/t.py::test_a"
        ),
        RegressionEntry(
            finding_class="ssrf", scenario_id="ssrf", status="covered", test="tests/t.py::test_b"
        ),
    )
)


def test_critical_regression_gate_passes_when_every_pinning_test_passed() -> None:
    decision = critical_regression_gate(
        REGISTRY, {"tests/t.py::test_a": True, "tests/t.py::test_b": True}
    )
    assert not decision.blocked


def test_critical_regression_gate_blocks_a_failed_pinning_test() -> None:
    decision = critical_regression_gate(
        REGISTRY, {"tests/t.py::test_a": False, "tests/t.py::test_b": True}
    )
    assert decision.blocked and decision.reason_code == "REGISTRY_TEST_FAILED"
    assert "bola" in decision.detail


def test_critical_regression_gate_blocks_a_test_that_did_not_run() -> None:
    decision = critical_regression_gate(REGISTRY, {"tests/t.py::test_a": True})
    assert decision.blocked and decision.reason_code == "REGISTRY_TEST_NOT_RUN"


# --- schema-drift gate ------------------------------------------------------------------------


def test_schema_drift_gate_passes_identical_digests() -> None:
    observed = schema_digests()
    assert not schema_drift_gate(observed, observed).blocked


def test_schema_drift_gate_blocks_a_drifted_digest() -> None:
    observed = schema_digests()
    baseline = {**observed, "scenario-1.3": "0" * 64}
    decision = schema_drift_gate(baseline, observed)
    assert decision.blocked and "drifted: scenario-1.3" in decision.detail


def test_schema_drift_gate_blocks_an_unrecorded_reference() -> None:
    """A new reference forces a deliberate baseline-bump commit, never a silent widening."""
    observed = {**schema_digests(), "new-document-2.0": "1" * 64}
    decision = schema_drift_gate(schema_digests(), observed)
    assert decision.blocked and "bump required" in decision.detail


def test_committed_schema_baseline_matches_the_current_code() -> None:
    """The standing drift check: the committed baseline and the code agree right now."""
    import json

    baseline = json.loads((ROOT / "baselines" / "schema-digests.json").read_text())["digests"]
    decision = schema_drift_gate(baseline, schema_digests())
    assert not decision.blocked, decision.detail


# --- risk-class gate and the pre-registered comparison ----------------------------------------


def metrics(
    risk_class: str = "prompt-injection",
    *,
    scenarios: int = 5,
    tp: int = 5,
    fn: int = 0,
    fp: int = 0,
    side_effects: int = 0,
) -> RiskClassMetrics:
    return RiskClassMetrics(
        risk_class=risk_class,
        scenarios=scenarios,
        seeded_true_positives=tp,
        seeded_false_negatives=fn,
        false_positives=fp,
        negative_controls=scenarios,
        defended_unauthorized_side_effects=side_effects,
    )


def baseline_of(*classes: RiskClassMetrics) -> RiskClassBaseline:
    return RiskClassBaseline(
        recorded_at=datetime(2026, 1, 1, tzinfo=UTC), corpus="test", classes=classes
    )


def test_one_newly_missed_seeded_finding_blocks_regardless_of_p_value() -> None:
    """The absolute floor: a lost detection is a fact, not a sample."""
    comparisons = compare_risk_classes(
        baseline_of(metrics()), [metrics(tp=4, fn=1)], alpha=0.000001
    )
    assert comparisons[0].blocked
    assert comparisons[0].reason_code == "NEWLY_MISSED_SEEDED_FINDING"
    assert comparisons[0].newly_missed_seeded_findings == 1


def test_added_scenarios_changing_denominators_do_not_block() -> None:
    comparisons = compare_risk_classes(baseline_of(metrics()), [metrics(scenarios=8, tp=8, fn=0)])
    assert not any(item.blocked for item in comparisons)


def test_a_new_risk_class_is_recorded_not_blocked() -> None:
    comparisons = compare_risk_classes(
        baseline_of(metrics()), [metrics(), metrics("covert-channel")]
    )
    new = [item for item in comparisons if item.risk_class == "covert-channel"]
    assert new and not new[0].blocked and new[0].reason_code == "NEW_RISK_CLASS"


def test_a_lost_risk_class_blocks() -> None:
    comparisons = compare_risk_classes(baseline_of(metrics()), [])
    assert comparisons[0].blocked and comparisons[0].reason_code == "RISK_CLASS_MISSING"


def test_new_false_positives_and_defended_side_effects_block() -> None:
    fp = compare_risk_classes(baseline_of(metrics()), [metrics(fp=1)])
    assert fp[0].blocked and fp[0].reason_code == "FALSE_POSITIVES_INCREASED"
    effects = compare_risk_classes(baseline_of(metrics()), [metrics(side_effects=1)])
    assert effects[0].blocked and effects[0].reason_code == "DEFENDED_SIDE_EFFECTS_INCREASED"


def test_statistical_branch_blocks_only_a_meaningful_losing_difference() -> None:
    """Same fn, lower recall (shrunk denominator): only the pre-registered test decides."""
    base = baseline_of(metrics(scenarios=30, tp=28, fn=2))
    worse = [metrics(scenarios=5, tp=3, fn=2)]
    at_alpha_one = compare_risk_classes(base, worse, alpha=1.0)
    assert at_alpha_one[0].blocked
    assert at_alpha_one[0].reason_code == "STATISTICAL_RECALL_REGRESSION"
    at_tiny_alpha = compare_risk_classes(base, worse, alpha=1e-9)
    assert not at_tiny_alpha[0].blocked
    assert at_tiny_alpha[0].reason_code == "WITHIN_BASELINE"
    assert at_tiny_alpha[0].p_value is not None


def test_risk_class_gate_wraps_the_comparison() -> None:
    blocked = risk_class_gate(baseline_of(metrics()), [metrics(tp=4, fn=1)])
    assert blocked.blocked and "NEWLY_MISSED_SEEDED_FINDING" in blocked.detail
    passed = risk_class_gate(baseline_of(metrics()), [metrics()])
    assert not passed.blocked


def test_fisher_exact_matches_known_values() -> None:
    # Classic 2x2 reference values for the two-sided test.
    assert fisher_exact_two_sided(1, 9, 11, 3) == pytest.approx(0.002759, abs=1e-5)
    assert fisher_exact_two_sided(3, 1, 1, 3) == pytest.approx(0.485714, abs=1e-5)
    assert fisher_exact_two_sided(0, 0, 0, 0) == 1.0
    assert fisher_exact_two_sided(5, 0, 5, 0) == 1.0
    with pytest.raises(ValueError):
        fisher_exact_two_sided(-1, 0, 0, 0)


# --- gate isolation: advisory verdicts cannot reach any gate ----------------------------------


def gate_inputs(summaries: list[RunSummary]) -> dict[str, object]:
    return {
        "events": [event(1, EventKind.POLICY, "permit"), event(2, EventKind.RESULT, "permit")],
        "limits": LIMITS,
        "summaries": summaries,
        "registry": REGISTRY,
        "outcomes": {"tests/t.py::test_a": True, "tests/t.py::test_b": True},
        "schema_baseline": schema_digests(),
        "risk_baseline": baseline_of(metrics()),
        "risk_current": [metrics()],
    }


def test_all_gates_pass_on_clean_binding_inputs() -> None:
    decisions = all_gates(**gate_inputs([summary()]))  # type: ignore[arg-type]
    assert len(decisions) == 5 and not any(decision.blocked for decision in decisions)
    assert {decision.gate for decision in decisions} == {
        "scope-bypass",
        "critical-regression",
        "schema-drift",
        "budget-failure",
        "risk-class-regression",
    }


def test_an_advisory_finding_is_rejected_at_the_gate_boundary() -> None:
    with pytest.raises(AdvisoryVerdictError):
        all_gates(**gate_inputs([summary(findings_provenance="advisory")]))  # type: ignore[arg-type]


def test_an_advisory_replay_verdict_is_rejected_at_the_gate_boundary() -> None:
    tainted = summary()
    assert tainted.replay is not None
    tainted = tainted.model_copy(
        update={
            "replay": tainted.replay.model_copy(
                update={"security": oracle("false", "pinned-stochastic")}
            )
        }
    )
    with pytest.raises(AdvisoryVerdictError):
        all_gates(**gate_inputs([tainted]))  # type: ignore[arg-type]


# --- junit parsing ----------------------------------------------------------------------------


def test_outcomes_from_junit_rebuilds_node_ids(tmp_path: Path) -> None:
    report = tmp_path / "junit.xml"
    report.write_text(
        """<?xml version="1.0" encoding="utf-8"?>
<testsuites><testsuite name="pytest">
  <testcase classname="tests.phase4.test_gates" name="test_pass" time="0.1"/>
  <testcase classname="tests.phase4.test_gates" name="test_fail" time="0.1">
    <failure message="boom"/>
  </testcase>
  <testcase classname="tests.phase4.test_gates" name="test_skip" time="0.0">
    <skipped message="gated"/>
  </testcase>
</testsuite></testsuites>
"""
    )
    outcomes = outcomes_from_junit(report)
    assert outcomes["tests/phase4/test_gates.py::test_pass"] is True
    assert outcomes["tests/phase4/test_gates.py::test_fail"] is False
    # A skipped pinning test is not a passing one: it blocks rather than slipping through.
    assert outcomes["tests/phase4/test_gates.py::test_skip"] is False
