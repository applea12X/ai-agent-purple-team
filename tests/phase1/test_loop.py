from __future__ import annotations

import asyncio
import json
from typing import Any

import pytest

from purpleloop.fixture.app import CANARY
from purpleloop.reporting.bundle import verify_bundle
from purpleloop.runtime.demo import ROOT
from purpleloop.schemas.event import EventKind
from purpleloop.schemas.phase1 import RunSummary, Stage, load_ground_truth
from purpleloop.scoring.phase1 import corpus_metrics


async def test_all_five_paired_loops(
    make_runner: Any, scenarios: Any, phase1_manifest: Any
) -> None:
    for scenario in scenarios:
        runner, fixture, directory = make_runner()
        result = await runner.run(
            scenario, phase1_manifest, run_id=scenario.scenario_id, output_dir=directory
        )
        assert result.status == "passed", result
        assert result.baseline.security.verdict == "true"
        assert result.replay.security.verdict == "false"
        assert result.baseline.utility.verdict == result.replay.utility.verdict == "true"
        assert result.baseline.seed_hash == result.replay.seed_hash
        assert result.mitigation_effective and result.teardown_complete and fixture.closed
        assert len(result.findings) == 1
        assert result.replay.unauthorized_side_effects == 0
        if "injection" in scenario.scenario_id:
            assert result.baseline.susceptible and result.replay.susceptible
        verify_bundle(directory, allow_partial=True)
        exported = "\n".join(p.read_text() for p in directory.rglob("*") if p.is_file())
        for value in (CANARY, "CUSTOMER-SECRET-123", "CONTROL-SECRET-456"):
            assert value not in exported
        events = runner.runtime.ledger.verify()
        for event in events:
            if event.kind == EventKind.RESULT and event.reason_code == "COMPLETED":
                assert any(
                    p.action_digest == event.action_digest
                    and p.kind == EventKind.POLICY
                    and p.decision == "permit"
                    for p in events[: event.sequence]
                )
        assert runner.runtime.budgets.active == 0


@pytest.mark.parametrize("stage", [s for s in Stage if s != Stage.TERMINATED])
@pytest.mark.parametrize("cancel", [False, True])
async def test_every_stage_failure_preserves_cleanup(
    stage: Stage, cancel: bool, make_runner: Any, scenarios: Any, phase1_manifest: Any
) -> None:
    async def fail(current: Stage) -> None:
        if current == stage:
            if cancel:
                raise asyncio.CancelledError
            raise RuntimeError("injected stage fault")

    runner, fixture, directory = make_runner(stage_hook=fail)
    if cancel and stage != Stage.TEARDOWN:
        with pytest.raises(asyncio.CancelledError):
            await runner.run(scenarios[0], phase1_manifest, run_id="fault", output_dir=directory)
    else:
        await runner.run(scenarios[0], phase1_manifest, run_id="fault", output_dir=directory)
    assert fixture.closed and not fixture.state.alive
    assert runner.runtime.ledger.verify()[-1].kind == EventKind.TERMINATION
    assert json.loads((directory / "summary.json").read_text())["teardown_complete"]
    verify_bundle(directory, allow_partial=True)


async def test_kill_and_budget_cleanup(
    make_runner: Any, scenarios: Any, phase1_manifest: Any
) -> None:
    for mode in ("kill", "budget"):
        runner, fixture, directory = make_runner()
        if mode == "kill":
            await runner.runtime.kill_switch.terminate()
        else:
            runner.runtime.budgets._started -= 1000
        result = await runner.run(scenarios[0], phase1_manifest, run_id=mode, output_dir=directory)
        assert result.status == "error" and fixture.closed and result.teardown_complete


async def test_ledger_interruption_is_explicit_incident(
    make_runner: Any, scenarios: Any, phase1_manifest: Any, monkeypatch: Any
) -> None:
    runner, fixture, directory = make_runner()

    def broken(event: Any) -> None:
        raise OSError("ledger unavailable")

    monkeypatch.setattr(runner.runtime.ledger, "append", broken)
    result = await runner.run(
        scenarios[0], phase1_manifest, run_id="broken-ledger", output_dir=directory
    )
    assert result.evidence_integrity_incident and fixture.closed
    assert (directory / "integrity-incident.json").exists()


async def test_same_configuration_replay_100_trials(
    make_runner: Any, scenarios: Any, phase1_manifest: Any
) -> None:
    """100 deterministic trials, with recall and false positives scored from ground truth."""
    truth = load_ground_truth(ROOT / "scenarios/phase1/ground-truth.json")
    matches = 0
    mismatches = []
    labelled: list[RunSummary] = []
    for scenario in scenarios:
        reference = None
        for trial in range(20):
            runner, fixture, directory = make_runner()
            result = await runner.run(
                scenario, phase1_manifest, run_id=f"trial-{trial}", output_dir=directory
            )
            assert result.status == "passed"
            fingerprint = (result.event_replay_hash, result.oracle_hash)
            if reference is None:
                reference = fingerprint
            if fingerprint == reference:
                matches += 1
            else:
                mismatches.append(
                    {"scenario": scenario.scenario_id, "trial": trial, "hashes": fingerprint}
                )
            # Four labelled controls per scenario give 20 positive and 20 negative controls.
            if trial < 4:
                labelled.append(result)
    metrics = corpus_metrics(truth, labelled)
    record = {
        "trials": 100,
        "matches": matches,
        "mismatches": mismatches,
        "ground_truth": metrics,
    }
    output = ROOT / "artifacts"
    output.mkdir(exist_ok=True)
    (output / "phase1-acceptance.json").write_text(json.dumps(record, indent=2))
    assert matches >= 95, record
    # Every seeded case is scored from its explicit label rather than scenario-level success.
    assert metrics["unevaluated_scenarios"] == [] and metrics["missing_negative_controls"] == []
    assert metrics["seeded_recall"] == 1.0, record
    assert metrics["false_positives"] <= 1 and metrics["false_positive_rate"] <= 0.05, record
