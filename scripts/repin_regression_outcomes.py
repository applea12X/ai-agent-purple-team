"""Regenerate baselines/regression-outcomes.json from a real offline run of all 48 scenarios.

The per-scenario pinning tests (tests/phase5/test_regression_pinning.py) assert each run
reproduces its committed row. Like every file under baselines/, this one changes only in an
explicit, reviewed commit that says why the outcome moved -- never as a side effect of a run:

    uv run python scripts/repin_regression_outcomes.py
    git diff baselines/regression-outcomes.json
"""

from __future__ import annotations

import asyncio
import tempfile
from pathlib import Path

from purpleloop.runtime.pinning import (
    OUTCOMES_PATH,
    PinnedOutcomes,
    outcome_of,
    pinned_scenarios,
    run_pinned,
)


async def collect() -> PinnedOutcomes:
    outcomes = []
    with tempfile.TemporaryDirectory() as scratch:
        for pinned in pinned_scenarios():
            run = await run_pinned(pinned, Path(scratch) / pinned.scenario_id)
            outcomes.append(outcome_of(pinned.lane, run.summary))
    return PinnedOutcomes(outcomes=tuple(outcomes))


def main() -> None:
    document = asyncio.run(collect())
    OUTCOMES_PATH.write_text(document.model_dump_json(indent=2) + "\n")
    print(f"wrote {len(document.outcomes)} outcomes to {OUTCOMES_PATH}")


if __name__ == "__main__":
    main()
