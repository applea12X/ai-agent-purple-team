"""Agreement statistics for advisory verdicts, reported with n and an interval.

Krippendorff's alpha over the three-category scale (true / false / abstain) is the headline,
because abstention is a real outcome here and plain Cohen's kappa has no place to put it --
abstention is neither agreement nor disagreement with a substantive label. Kappa is reported too,
over the abstention-excluded subset, with its own n. Open question 3 in the plan, answered as
recommended.

The interval is a deterministic bootstrap: the resample order comes from a fixed seed, so the
same inputs give the same interval. The method is named wherever the number is reported; a
bootstrap interval on a small n is a rough guide, and calling it anything else would overstate it.
"""

from __future__ import annotations

import random
from collections import Counter
from collections.abc import Sequence

Pair = tuple[str, str]


def krippendorff_alpha(pairs: Sequence[Pair]) -> float:
    """Nominal alpha for two coders and no missing values.

    Built from the coincidence matrix rather than a shortcut, so adding a third coder later is a
    change of input rather than a change of formula. Returns 1.0 for an empty input, which is
    reported alongside ``n=0`` so it can never be mistaken for a measurement.
    """
    if not pairs:
        return 1.0
    coincidence: Counter[tuple[str, str]] = Counter()
    for first, second in pairs:
        # Each unit contributes both ordered pairs, divided by (coders - 1) = 1.
        coincidence[(first, second)] += 1
        coincidence[(second, first)] += 1
    totals: Counter[str] = Counter()
    for (first, _), count in coincidence.items():
        totals[first] += count
    n = sum(totals.values())
    if n <= 1:
        return 1.0
    observed = sum(count for (first, second), count in coincidence.items() if first != second)
    expected = sum(
        totals[first] * totals[second] for first in totals for second in totals if first != second
    ) / (n - 1)
    if expected == 0:
        return 1.0
    return 1.0 - observed / expected


def cohen_kappa(pairs: Sequence[Pair]) -> tuple[float | None, int]:
    """Kappa over the supplied pairs, with its n. ``None`` when it is undefined."""
    n = len(pairs)
    if n == 0:
        return None, 0
    agree = sum(first == second for first, second in pairs) / n
    first_counts = Counter(first for first, _ in pairs)
    second_counts = Counter(second for _, second in pairs)
    chance = sum(
        (first_counts[label] / n) * (second_counts[label] / n)
        for label in set(first_counts) | set(second_counts)
    )
    if chance >= 1.0:
        return None, n
    return (agree - chance) / (1 - chance), n


def bootstrap_interval(
    pairs: Sequence[Pair], *, resamples: int = 1000, seed: int = 20260908, level: float = 0.95
) -> tuple[float, float]:
    """Deterministic percentile bootstrap interval for alpha."""
    if len(pairs) < 2:
        return (0.0, 1.0)
    rng = random.Random(seed)  # noqa: S311 -- a seeded resampler, deliberately reproducible
    values: list[float] = []
    for _ in range(resamples):
        sample = [pairs[rng.randrange(len(pairs))] for _ in range(len(pairs))]
        values.append(krippendorff_alpha(sample))
    values.sort()
    tail = (1 - level) / 2
    low = values[max(0, int(tail * len(values)) - 1)]
    high = values[min(len(values) - 1, int((1 - tail) * len(values)))]
    return (round(low, 6), round(high, 6))


def order_swap_consistency(verdicts: Sequence[tuple[str, str]]) -> tuple[float, int]:
    """Fraction of cases whose verdict is unchanged when the evidence order is reversed."""
    if not verdicts:
        return 1.0, 0
    stable = sum(first == second for first, second in verdicts)
    return stable / len(verdicts), len(verdicts)
