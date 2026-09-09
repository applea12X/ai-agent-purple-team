"""Stochastic reporting: four separate numbers, each carrying its n, seed policy, and pin.

Nothing here composites. Clean utility, utility under attack, attack success, and executed
unauthorized side effects are four measurements of four different things, and a single "security
score" built from them would hide exactly the disagreements a reader needs -- a model that
complies while the kernel blocks every tool call, or a defense that stops an attack by making the
assistant useless.

Every :class:`Measurement` records its provenance. A figure built from repeated model calls is
``pinned-stochastic`` and refuses to serialize without a model pin; a figure from a single
deterministic run is ``deterministic`` with n=1 and a degenerate interval. ``require_binding``
keeps the first kind out of every gate.
"""

from __future__ import annotations

import random
from collections.abc import Sequence
from math import sqrt

from purpleloop.schemas.phase1 import RunSummary
from purpleloop.schemas.phase3 import (
    BINDING_PROVENANCE,
    Measurement,
    ModelPin,
    RepetitionRecord,
    RepetitionSet,
    StochasticReport,
    TokenAccounting,
    VerdictProvenance,
)

TOLERANCE_PERCENT = 10.0
BOOTSTRAP_SEED = 20260909


def wilson_interval(successes: int, n: int, *, z: float = 1.959963985) -> tuple[float, float]:
    """Wilson score interval for a proportion. Chosen because n here is small by design."""
    if n == 0:
        return (0.0, 1.0)
    phat = successes / n
    denominator = 1 + z * z / n
    centre = (phat + z * z / (2 * n)) / denominator
    margin = z * sqrt(phat * (1 - phat) / n + z * z / (4 * n * n)) / denominator
    return (round(max(0.0, centre - margin), 6), round(min(1.0, centre + margin), 6))


def mean_interval(values: Sequence[float], *, resamples: int = 1000) -> tuple[float, float]:
    """Deterministic percentile bootstrap for the mean of a count. The method is named on report."""
    if not values:
        return (0.0, 0.0)
    if len(values) == 1:
        return (round(values[0], 6), round(values[0], 6))
    rng = random.Random(BOOTSTRAP_SEED)  # noqa: S311 -- seeded resampler, deliberately reproducible
    means = sorted(
        sum(values[rng.randrange(len(values))] for _ in values) / len(values)
        for _ in range(resamples)
    )
    return (round(means[int(0.025 * len(means))], 6), round(means[int(0.975 * len(means)) - 1], 6))


def _provenance(repetitions: RepetitionSet) -> VerdictProvenance:
    """A set of one deterministic trial stays deterministic; anything repeated is stochastic."""
    if repetitions.requested == 1 and all(
        record.provenance == BINDING_PROVENANCE for record in repetitions.records
    ):
        return BINDING_PROVENANCE
    return "pinned-stochastic"


def proportion(
    successes: int, repetitions: RepetitionSet, *, provenance: VerdictProvenance
) -> Measurement:
    n = repetitions.completed
    low, high = wilson_interval(successes, n)
    return Measurement(
        provenance=provenance,
        value=round(successes / n, 6) if n else 0.0,
        n=n,
        ci_low=low,
        ci_high=high,
        seed_policy=repetitions.seed_policy,
        model_pin_id=repetitions.model_pin_id,
        excluded=repetitions.excluded,
    )


def count_mean(
    values: Sequence[float], repetitions: RepetitionSet, *, provenance: VerdictProvenance
) -> Measurement:
    low, high = mean_interval(values)
    return Measurement(
        provenance=provenance,
        value=round(sum(values) / len(values), 6) if values else 0.0,
        n=len(values),
        ci_low=low,
        ci_high=high,
        seed_policy=repetitions.seed_policy,
        model_pin_id=repetitions.model_pin_id,
        excluded=repetitions.excluded,
    )


def record_from(summary: RunSummary, index: int, *, model_pin_id: str | None) -> RepetitionRecord:
    baseline = summary.baseline
    return RepetitionRecord(
        provenance="pinned-stochastic",
        repetition_index=index,
        run_id=summary.run_id,
        status=summary.status,
        security_verdict=baseline.security.verdict if baseline else "inconclusive",
        utility_verdict=baseline.utility.verdict if baseline else "inconclusive",
        utility_under_attack_verdict=(
            baseline.utility_under_attack.verdict
            if baseline is not None and baseline.utility_under_attack is not None
            else "not-measured"
        ),
        susceptible=bool(baseline and baseline.susceptible),
        unauthorized_side_effects=baseline.unauthorized_side_effects if baseline else 0,
        tokens_used=summary.tokens_used,
        cost_microusd=summary.cost_microusd,
        model_pin_id=model_pin_id,
        judge=baseline.judge if baseline else None,
    )


def stochastic_report(repetitions: RepetitionSet) -> StochasticReport:
    """The four numbers, kept apart, plus the reproducibility the repetitions support."""
    records = repetitions.records
    provenance = _provenance(repetitions)
    clean = sum(r.utility_verdict == "true" for r in records)
    under_attack = sum(r.utility_under_attack_verdict == "true" for r in records)
    measured_under_attack = [r for r in records if r.utility_under_attack_verdict != "not-measured"]
    success = sum(r.security_verdict == "true" for r in records)
    side_effects = [float(r.unauthorized_side_effects) for r in records]
    # Reproducible means every completed repetition reached the same security verdict, and there
    # was more than one. A single paired run cannot establish it, and does not claim to.
    verdicts = {r.security_verdict for r in records}
    return StochasticReport(
        scenario_id=repetitions.scenario_id,
        clean_utility=proportion(clean, repetitions, provenance=provenance),
        utility_under_attack=(
            proportion(under_attack, repetitions, provenance=provenance)
            if measured_under_attack
            else Measurement(
                provenance=provenance,
                value=0.0,
                n=0,
                ci_low=0.0,
                ci_high=1.0,
                seed_policy=repetitions.seed_policy,
                model_pin_id=repetitions.model_pin_id,
                excluded=repetitions.requested,
            )
        ),
        attack_success=proportion(success, repetitions, provenance=provenance),
        executed_unauthorized_side_effects=count_mean(
            side_effects, repetitions, provenance=provenance
        ),
        repetitions=repetitions,
        reproducible=len(records) > 1 and len(verdicts) == 1,
    )


def reproducibility_basis(report: StochasticReport) -> str:
    completed = report.repetitions.completed
    if completed <= 1:
        return "single paired run; repetitions not executed"
    if report.reproducible:
        return f"{completed} repetitions agreed on the security verdict"
    return f"{completed} repetitions disagreed on the security verdict"


def estimate_tokens(pin: ModelPin, *, model_calls: int, prompt_chars: int) -> tuple[int, int]:
    """Pre-run token and cost estimate for a scenario, from the pin's own declared price.

    A crude but stated proxy: four characters per input token and the pin's maximum output. It is
    reported against actual with the same tolerance as every other resource, so an estimate that
    is wrong shows up as a delta rather than as silence.
    """
    input_tokens = model_calls * max(1, prompt_chars // 4)
    output_tokens = model_calls * pin.decoding.max_output_tokens
    return input_tokens + output_tokens, pin.cost_microusd(input_tokens, output_tokens)


def token_accounting(
    *, estimated_tokens: int, actual_tokens: int, estimated_cost: int, actual_cost: int
) -> TokenAccounting:
    def delta(estimated: int, actual: int) -> float:
        if estimated == 0:
            return 0.0 if actual == 0 else 100.0
        return round((actual - estimated) / estimated * 100, 6)

    deltas = {
        "tokens": delta(estimated_tokens, actual_tokens),
        "cost_microusd": delta(estimated_cost, actual_cost),
    }
    return TokenAccounting(
        estimated_tokens=estimated_tokens,
        actual_tokens=actual_tokens,
        estimated_cost_microusd=estimated_cost,
        actual_cost_microusd=actual_cost,
        delta_percent=deltas,
        within_tolerance={name: abs(value) <= TOLERANCE_PERCENT for name, value in deltas.items()},
    )
