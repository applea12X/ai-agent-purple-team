"""The risk-class gate blocks a removed scenario (WP5.0.7 finding, fixed in WP5.1).

Both sides: a removal blocks with ``SCENARIOS_REMOVED`` even when every rate is unchanged; an
addition never blocks. And the committed corpus, gated against its committed baseline, is
decided exactly as before.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime

from purpleloop.reporting.gates import risk_class_gate
from purpleloop.runtime.demo import ROOT
from purpleloop.schemas.phase4 import RiskClassBaseline, RiskClassMetrics
from purpleloop.scoring.phase4 import compare_risk_classes


def metrics(name: str = "approval-spoofing", scenarios: int = 2, tp: int = 2) -> RiskClassMetrics:
    return RiskClassMetrics(
        risk_class=name,
        scenarios=scenarios,
        seeded_true_positives=tp,
        seeded_false_negatives=0,
        false_positives=0,
        negative_controls=scenarios,
        defended_unauthorized_side_effects=0,
    )


def baseline(*classes: RiskClassMetrics) -> RiskClassBaseline:
    return RiskClassBaseline(
        recorded_at=datetime(2026, 1, 1, tzinfo=UTC), corpus="test", classes=classes
    )


def test_a_removed_scenario_blocks_even_at_identical_rates() -> None:
    """The exact WP5.0.7 case: 2/2 in the baseline, 1/1 now. Recall is 1.0 both times."""
    base, current = baseline(metrics()), [metrics(scenarios=1, tp=1)]
    assert not any(item.blocked for item in compare_risk_classes(base, current))
    decision = risk_class_gate(base, current)
    assert decision.blocked and decision.reason_code == "SCENARIOS_REMOVED"
    assert "approval-spoofing: 1 scenario(s) against 2 in the baseline" in decision.detail


def test_an_added_scenario_or_class_does_not_block() -> None:
    base = baseline(metrics())
    grown = risk_class_gate(base, [metrics(scenarios=3, tp=3)])
    assert not grown.blocked and grown.reason_code == "WITHIN_BASELINE"
    new_class = risk_class_gate(base, [metrics(), metrics("covert-channel", 1, 1)])
    assert not new_class.blocked


def test_an_existing_regression_keeps_its_reason() -> None:
    """Removal plus a newly missed finding still reports the regression it always reported."""
    base = baseline(metrics(scenarios=3, tp=3))
    worse = RiskClassMetrics(
        risk_class="approval-spoofing",
        scenarios=2,
        seeded_true_positives=1,
        seeded_false_negatives=1,
        false_positives=0,
        negative_controls=2,
        defended_unauthorized_side_effects=0,
    )
    decision = risk_class_gate(base, [worse])
    assert decision.blocked and decision.reason_code == "RISK_CLASS_REGRESSION"
    lost = risk_class_gate(base, [])
    assert lost.blocked and lost.reason_code == "RISK_CLASS_REGRESSION"


def test_the_committed_corpus_is_decided_as_before() -> None:
    committed = RiskClassBaseline.model_validate(
        json.loads((ROOT / "baselines" / "corpus-baseline.json").read_text())
    )
    decision = risk_class_gate(committed, list(committed.classes))
    assert not decision.blocked and decision.reason_code == "WITHIN_BASELINE"
    # Removing any one scenario from any one class now blocks at the gate itself.
    for entry in committed.classes:
        if entry.scenarios == 0:
            continue
        fewer = entry.model_copy(
            update={
                "scenarios": entry.scenarios - 1,
                "seeded_true_positives": max(entry.seeded_true_positives - 1, 0),
                "negative_controls": max(entry.negative_controls - 1, 0),
            }
        )
        current = [fewer if c.risk_class == entry.risk_class else c for c in committed.classes]
        outcome = risk_class_gate(committed, current)
        assert outcome.blocked, entry.risk_class
        assert outcome.reason_code in {"SCENARIOS_REMOVED", "RISK_CLASS_REGRESSION"}
