from __future__ import annotations

from pathlib import Path

from inspect_ai import Task, eval_async
from inspect_ai.dataset import MemoryDataset, Sample
from inspect_ai.model import ModelOutput
from inspect_ai.scorer import Score, Scorer, Target, accuracy, scorer
from inspect_ai.solver import Generate, Solver, TaskState, solver

from purpleloop.adapters import inspect_model as _registration  # noqa: F401
from purpleloop.reporting.bundle import inventory, verify_bundle
from purpleloop.runtime.runner import PurpleTeamRunner
from purpleloop.schemas.authorization import AuthorizationManifest
from purpleloop.schemas.phase1 import Phase1Scenario, RunSummary


@scorer(metrics=[accuracy()])
def canonical_scorer() -> Scorer:
    async def score(state: TaskState, target: Target) -> Score:
        summary = RunSummary.model_validate(state.metadata["purpleloop"])
        return Score(
            value=1 if summary.status == "passed" else 0,
            answer=summary.status,
            explanation=summary.reason,
            metadata={
                "evidence": [e for f in summary.findings for e in f.evidence_ids],
                "oracle_hash": summary.oracle_hash,
            },
        )

    return score


def dataset(scenarios: list[Phase1Scenario]) -> MemoryDataset:
    return MemoryDataset(
        [
            Sample(
                id=s.scenario_id,
                input=s.legitimate_objective,
                metadata={"scenario": s.model_dump(mode="json")},
            )
            for s in scenarios
        ]
    )


async def evaluate_runner(
    runner: PurpleTeamRunner,
    scenario: Phase1Scenario,
    manifest: AuthorizationManifest,
    *,
    run_id: str,
    output_dir: Path,
    model_fixture: Path,
) -> RunSummary:
    result: list[RunSummary] = []

    @solver
    def run_canonical() -> Solver:
        async def solve(state: TaskState, generate: Generate) -> TaskState:
            summary = await runner.run(scenario, manifest, run_id=run_id, output_dir=output_dir)
            result.append(summary)
            state.metadata["purpleloop"] = summary.model_dump(mode="json")
            state.output = ModelOutput.from_content("purpleloop/offline", summary.status)
            state.completed = True
            return state

        return solve

    task = Task(
        name="purpleloop-phase1",
        dataset=dataset([scenario]),
        solver=run_canonical(),
        scorer=canonical_scorer(),
    )
    logs = await eval_async(
        task,
        model="purpleloop/offline",
        model_args={"fixture_path": str(model_fixture)},
        log_dir=str(output_dir / "inspect"),
        log_format="json",
        max_samples=1,
        retry_on_error=0,
        fail_on_error=True,
        log_model_api=False,
    )
    if not result or any(log.status != "success" for log in logs):
        raise RuntimeError("Inspect evaluation failed; partial artifacts retained")
    inventory(output_dir, complete=True)
    verify_bundle(output_dir)
    return result[0]
