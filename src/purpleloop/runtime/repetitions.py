"""Repetition driver: run one scenario N times and aggregate honestly.

A repetition that does not complete is counted as an exclusion and reported beside the number it
affects, never dropped from a denominator. That is the whole point of carrying ``requested``
alongside ``records``.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from pathlib import Path

from purpleloop.runtime.runner import PurpleTeamRunner
from purpleloop.schemas.authorization import AuthorizationManifest
from purpleloop.schemas.phase1 import Finding, Phase1Scenario, RunSummary
from purpleloop.schemas.phase3 import RepetitionSet, StochasticReport
from purpleloop.scoring.phase3 import record_from, reproducibility_basis, stochastic_report

RunnerFactory = Callable[[int], tuple[PurpleTeamRunner, Path]]
#: How one repetition is executed. Defaults to the runner's own loop; the CLI passes the Inspect
#: bridge instead, so a demo bundle carries an Inspect log and verifies like every other bundle.
Execute = Callable[
    [PurpleTeamRunner, Phase1Scenario, AuthorizationManifest, str, Path], Awaitable[RunSummary]
]


async def _default_execute(
    runner: PurpleTeamRunner,
    scenario: Phase1Scenario,
    manifest: AuthorizationManifest,
    run_id: str,
    directory: Path,
) -> RunSummary:
    return await runner.run(scenario, manifest, run_id=run_id, output_dir=directory)


async def run_repetitions(
    scenario: Phase1Scenario,
    manifest: AuthorizationManifest,
    factory: RunnerFactory,
    *,
    repetitions: int,
    run_id: str,
    seed_policy: str = "fixed-per-repetition",
    execute: Execute | None = None,
) -> tuple[StochasticReport, list[RunSummary]]:
    """Run ``repetitions`` independent evaluations and aggregate them."""
    if repetitions < 1:
        raise ValueError("at least one repetition is required")
    runner_execute = execute or _default_execute
    pin_id = manifest.phase3.model_pins[0].pin_id if manifest.phase3 else None
    summaries: list[RunSummary] = []
    exclusions: list[str] = []
    for index in range(repetitions):
        runner, directory = factory(index)
        try:
            summaries.append(
                await runner_execute(runner, scenario, manifest, f"{run_id}-{index}", directory)
            )
        except Exception as exc:  # noqa: BLE001 -- an excluded repetition is data, not a crash
            # Recorded with its reason and reported beside every number it reduces. Dropping it
            # silently would inflate each rate below by shrinking the denominator.
            exclusions.append(f"{index}: {type(exc).__name__}")
    repetition_set = RepetitionSet(
        scenario_id=scenario.scenario_id,
        requested=repetitions,
        records=tuple(
            record_from(summary, index, model_pin_id=pin_id)
            for index, summary in enumerate(summaries)
        ),
        seed_policy=seed_policy,
        model_pin_id=pin_id,
        exclusion_reasons=tuple(exclusions),
    )
    return stochastic_report(repetition_set), summaries


def apply_reproducibility(summary: RunSummary, report: StochasticReport) -> RunSummary:
    """Answer ``Finding.reproducible`` from the repetition set, and say what it is based on."""
    basis = reproducibility_basis(report)
    findings: tuple[Finding, ...] = tuple(
        finding.model_copy(
            update={"reproducible": report.reproducible, "reproducibility_basis": basis}
        )
        for finding in summary.findings
    )
    return summary.model_copy(update={"findings": findings, "stochastic": report})
