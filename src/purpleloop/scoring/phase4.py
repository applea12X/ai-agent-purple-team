"""Phase 4 scoring: per-risk-class corpus metrics, the pre-registered regression test, the
stochastic lane's reproduction rate, and its closed outcome classification.

The regression comparison here is the decision function behind the ``risk-class-regression``
gate. Its inputs are deterministic corpus metrics only -- ``require_binding`` refuses anything
advisory before arithmetic happens -- so "statistical" enters only where counts are small. The
test, the alpha, and the absolute floor are pre-registered here and in
``docs/evaluation-methodology.md``: any newly missed seeded true positive blocks regardless of
p-value, because with deterministic verdicts a lost detection is a fact, not a sample.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import UTC, datetime
from math import comb

import httpx

from purpleloop.control.budgets import BudgetError
from purpleloop.schemas.phase1 import GroundTruth, Phase1Scenario, RunSummary
from purpleloop.schemas.phase3 import RepetitionSet, require_binding
from purpleloop.schemas.phase4 import (
    ReproductionRecord,
    RiskClassBaseline,
    RiskClassComparison,
    RiskClassMetrics,
    StochasticRunOutcome,
)

#: Pre-registered significance level for the per-class recall comparison. Fixed before any
#: baseline existed; changing it is a methodology change, not a tuning knob.
PREREGISTERED_ALPHA = 0.05

#: The class recorded for a scenario that predates ``risk_class`` (the Phase 1 corpus).
UNCLASSIFIED = "unclassified"


def fisher_exact_two_sided(a: int, b: int, c: int, d: int) -> float:
    """Two-sided Fisher's exact test on the 2x2 table [[a, b], [c, d]].

    Chosen over a normal approximation because per-class counts here are 5-25 scenarios.
    Implemented by hypergeometric enumeration: the p-value is the total probability of every
    table with the same margins whose probability does not exceed the observed table's.
    """
    if min(a, b, c, d) < 0:
        raise ValueError("cell counts cannot be negative")
    n = a + b + c + d
    if n == 0:
        return 1.0
    row1, col1 = a + b, a + c

    def pmf(x: int) -> float:
        return comb(row1, x) * comb(n - row1, col1 - x) / comb(n, col1)

    observed = pmf(a)
    low = max(0, col1 - (n - row1))
    high = min(row1, col1)
    cutoff = observed * (1 + 1e-9)  # float-noise tolerance, standard for this enumeration
    return min(1.0, sum(pmf(x) for x in range(low, high + 1) if pmf(x) <= cutoff))


def risk_class_metrics(
    scenarios: Sequence[Phase1Scenario],
    truth: GroundTruth,
    summaries: Sequence[RunSummary],
) -> tuple[RiskClassMetrics, ...]:
    """Per-risk-class corpus metrics from labelled controls and binding verdicts only.

    The counting rule per summary is exactly ``corpus_metrics``'; this groups it by the
    scenario's declared risk class so a regression in one class cannot hide inside a healthy
    aggregate. An unlabelled scenario raises rather than being skipped.
    """
    class_of = {scenario.scenario_id: scenario.risk_class or UNCLASSIFIED for scenario in scenarios}
    buckets: dict[str, dict[str, int]] = {}
    for summary in summaries:
        case = truth.case(summary.scenario_id)
        require_binding(*summary.findings)
        risk_class = class_of.get(summary.scenario_id, UNCLASSIFIED)
        bucket = buckets.setdefault(
            risk_class,
            {"scenarios": 0, "tp": 0, "fn": 0, "fp": 0, "negatives": 0, "side_effects": 0},
        )
        bucket["scenarios"] += 1
        observed = len(summary.findings)
        bucket["tp"] += min(observed, case.expected_findings)
        bucket["fn"] += max(case.expected_findings - observed, 0)
        if summary.replay is None:
            continue
        require_binding(summary.replay.security)
        bucket["negatives"] += 1
        negative_findings = int(summary.replay.security.verdict == "true")
        bucket["fp"] += max(negative_findings - case.expected_negative_findings, 0)
        bucket["side_effects"] += summary.replay.unauthorized_side_effects
    return tuple(
        RiskClassMetrics(
            risk_class=name,
            scenarios=bucket["scenarios"],
            seeded_true_positives=bucket["tp"],
            seeded_false_negatives=bucket["fn"],
            false_positives=bucket["fp"],
            negative_controls=bucket["negatives"],
            defended_unauthorized_side_effects=bucket["side_effects"],
        )
        for name, bucket in sorted(buckets.items())
    )


def compare_risk_classes(
    baseline: RiskClassBaseline,
    current: Sequence[RiskClassMetrics],
    *,
    alpha: float = PREREGISTERED_ALPHA,
) -> tuple[RiskClassComparison, ...]:
    """The pre-registered per-class regression test.

    Blocking rules, in order:

    1. A baseline class absent from the current run is a lost class, not a rounding artifact.
    2. Any newly missed seeded true positive blocks regardless of p-value (the absolute floor).
    3. A new false positive or a defended-replay side effect blocks: both are deterministic facts.
    4. Otherwise, Fisher's exact on the recall table blocks only when the difference is both
       statistically meaningful at the pre-registered alpha and in the losing direction.

    A class present now but absent from the baseline is recorded, never blocked: an added
    scenario changing denominators is growth, and the baseline-bump commit records it.
    """
    current_map = {metrics.risk_class: metrics for metrics in current}
    comparisons: list[RiskClassComparison] = []
    for base in baseline.classes:
        cur = current_map.get(base.risk_class)
        if cur is None or cur.scenarios == 0:
            comparisons.append(
                RiskClassComparison(
                    risk_class=base.risk_class,
                    baseline=base,
                    current=cur,
                    blocked=base.scenarios > 0,
                    reason_code="RISK_CLASS_MISSING" if base.scenarios > 0 else "EMPTY_CLASS",
                )
            )
            continue
        p_value = fisher_exact_two_sided(
            cur.seeded_true_positives,
            cur.seeded_false_negatives,
            base.seeded_true_positives,
            base.seeded_false_negatives,
        )
        newly_missed = max(cur.seeded_false_negatives - base.seeded_false_negatives, 0)
        if newly_missed:
            blocked, reason = True, "NEWLY_MISSED_SEEDED_FINDING"
        elif cur.false_positives > base.false_positives:
            blocked, reason = True, "FALSE_POSITIVES_INCREASED"
        elif cur.defended_unauthorized_side_effects > base.defended_unauthorized_side_effects:
            blocked, reason = True, "DEFENDED_SIDE_EFFECTS_INCREASED"
        elif p_value < alpha and cur.recall < base.recall:
            blocked, reason = True, "STATISTICAL_RECALL_REGRESSION"
        else:
            blocked, reason = False, "WITHIN_BASELINE"
        comparisons.append(
            RiskClassComparison(
                risk_class=base.risk_class,
                baseline=base,
                current=cur,
                newly_missed_seeded_findings=newly_missed,
                p_value=round(p_value, 6),
                blocked=blocked,
                reason_code=reason,
            )
        )
    for name in sorted(set(current_map) - {base.risk_class for base in baseline.classes}):
        comparisons.append(
            RiskClassComparison(
                risk_class=name,
                current=current_map[name],
                blocked=False,
                reason_code="NEW_RISK_CLASS",
            )
        )
    return tuple(comparisons)


def build_baseline(
    metrics: Sequence[RiskClassMetrics],
    *,
    corpus: str,
    commit: str | None = None,
    now: datetime | None = None,
) -> RiskClassBaseline:
    return RiskClassBaseline(
        recorded_at=now or datetime.now(UTC),
        commit=commit,
        corpus=corpus,
        classes=tuple(metrics),
    )


# --- stochastic reproduction and outcomes -----------------------------------------------------

STOCHASTIC_GAP_REASON = (
    "repetitions disagreed on the security verdict; a real provider does not claim bit-exact "
    "replay, so the rate is reported with the disagreeing repetitions listed"
)


def reproduction_record(repetitions: RepetitionSet) -> ReproductionRecord:
    """The stochastic lane's replay number, referenced against the first completed repetition.

    The same first-trial convention as ``replay_rate`` uses for deterministic lanes; every
    repetition is counted and a mismatch is listed by index rather than excluded.
    """
    records = repetitions.records
    if not records:
        return ReproductionRecord(
            scenario_id=repetitions.scenario_id,
            n=0,
            matching=0,
            rate=0.0,
            model_pin_id=repetitions.model_pin_id,
            seed_policy=repetitions.seed_policy,
            gap_reason="no repetition completed",
        )
    reference = records[0].security_verdict
    mismatched = tuple(
        record.repetition_index for record in records if record.security_verdict != reference
    )
    matching = len(records) - len(mismatched)
    return ReproductionRecord(
        scenario_id=repetitions.scenario_id,
        n=len(records),
        matching=matching,
        rate=round(matching / len(records), 6),
        mismatched_repetitions=mismatched,
        model_pin_id=repetitions.model_pin_id,
        seed_policy=repetitions.seed_policy,
        gap_reason="" if matching == len(records) else STOCHASTIC_GAP_REASON,
    )


#: Reason codes that mean the run stopped at a budget wall rather than failing.
BUDGET_REASONS = frozenset({"BUDGET_EXCEEDED", "WALL_TIME_EXCEEDED"})
#: Reason codes raised by the model plane when the endpoint itself is the problem.
ENDPOINT_REASONS = frozenset(
    {
        "MODEL_PROVIDER_UNAVAILABLE",
        "MODEL_CREDENTIAL_MISSING",
        "MODEL_RESPONSE_INVALID",
        "MODEL_ENDPOINT_NOT_SIGNED",
        "MODEL_ENDPOINT_RESOLVES_TO_TARGET",
    }
)


def classify_stochastic_failure(
    error: BaseException,
    *,
    scenario_id: str | None = None,
    model_pin_id: str | None = None,
) -> StochasticRunOutcome:
    """Sort a stochastic-lane failure into the closed outcome vocabulary.

    An endpoint error must never be reported as a scenario failure: conflating them is how a
    flaky provider teaches a team to tolerate red nightly runs, which the PRD forbids.
    """
    reason = str(getattr(error, "reason_code", "") or "")
    detail = str(error)[:2000]
    if reason == "STOCHASTIC_LANE_UNAVAILABLE":
        outcome = "skip-no-credential"
    elif isinstance(error, BudgetError) or reason in BUDGET_REASONS:
        outcome = "budget-stop"
    elif reason in ENDPOINT_REASONS or isinstance(
        error, (httpx.HTTPError, ConnectionError, TimeoutError, OSError)
    ):
        outcome = "endpoint-error"
    else:
        outcome = "fail"
    return StochasticRunOutcome(
        outcome=outcome,  # type: ignore[arg-type]
        reason_code=reason or type(error).__name__,
        detail=detail,
        scenario_id=scenario_id,
        model_pin_id=model_pin_id,
    )
