"""Scripted Phase 2 acceptance measurements. Numbers are written to artifacts/, never inferred."""

from __future__ import annotations

import json
import time
from typing import Any

from purpleloop.runtime.demo import ROOT
from purpleloop.scoring.phase2 import replay_rate


async def test_100_isolated_runs_no_cross_run_leak(
    make_supportlab_runner: Any, supportlab_scenarios: Any, supportlab_signed: Any
) -> None:
    """100 consecutive isolated runs; every failure is reported, never rerun until clean."""
    scenarios = supportlab_scenarios
    seed_hashes: dict[str, str] = {}
    failures: list[dict[str, Any]] = []
    fingerprints: dict[str, list[tuple[str | None, str | None]]] = {}
    completeness: list[float] = []
    started = time.monotonic()
    runs = 0
    for index in range(100):
        scenario = scenarios[index % len(scenarios)]
        runner, fixture, directory = make_supportlab_runner()
        result = await runner.run(
            scenario, supportlab_signed, run_id=f"iso-{index}", output_dir=directory
        )
        runs += 1
        if result.status != "passed":
            failures.append(
                {"run": index, "scenario": scenario.scenario_id, "reason": result.reason}
            )
            continue
        # Cross-run leak detection: a fresh run of the same scenario must start from the identical
        # seeded state hash. A prior run's writes leaking in would change it.
        prior = seed_hashes.setdefault(scenario.scenario_id, result.baseline.seed_hash)
        if prior != result.baseline.seed_hash:
            failures.append({"run": index, "scenario": scenario.scenario_id, "leak": True})
        assert not fixture.state.database.provisioned  # torn down, no shared handle
        fingerprints.setdefault(scenario.scenario_id, []).append(
            (result.event_replay_hash, result.oracle_hash)
        )
        completeness.append(result.evidence_completeness.completeness)
    elapsed = time.monotonic() - started
    per_scenario_replay = {sid: replay_rate(items)["rate"] for sid, items in fingerprints.items()}
    record = {
        "runs": runs,
        "failures": failures,
        "distinct_scenarios": len(seed_hashes),
        "min_evidence_completeness": min(completeness) if completeness else 0.0,
        "per_scenario_replay_rate": per_scenario_replay,
        "wall_seconds": round(elapsed, 2),
    }
    output = ROOT / "artifacts"
    output.mkdir(exist_ok=True)
    (output / "phase2-isolation.json").write_text(json.dumps(record, indent=2))
    assert failures == [], record
    assert min(per_scenario_replay.values()) == 1.0, record
    assert record["min_evidence_completeness"] >= 0.99, record


async def test_reset_time_and_cross_engine_hash() -> None:
    """Measure per-leg template reset time and confirm SQLite matches a fresh seed."""
    from purpleloop.fixture.supportlab import seed
    from purpleloop.fixture.supportlab.database import SqliteDatabase

    db = SqliteDatabase()
    db.provision()
    seed.apply(db, 42)
    baseline = db.state_hash()
    samples = []
    for _ in range(20):
        db.execute("UPDATE tickets SET subject = 'x'")
        db.commit()
        start = time.perf_counter()
        db.reset()
        samples.append(time.perf_counter() - start)
        assert db.state_hash() == baseline
    db.teardown()
    fresh = SqliteDatabase()
    fresh.provision()
    seed.apply(fresh, 42)
    assert fresh.state_hash() == baseline
    fresh.teardown()
    record = {
        "reset_samples": len(samples),
        "mean_reset_ms": round(sum(samples) / len(samples) * 1000, 3),
    }
    (ROOT / "artifacts").mkdir(exist_ok=True)
    (ROOT / "artifacts" / "phase2-reset.json").write_text(json.dumps(record, indent=2))
    assert record["mean_reset_ms"] < 200


async def test_browser_emergency_stop_is_measured(
    make_supportlab_runner: Any, supportlab_scenarios: Any, supportlab_signed: Any
) -> None:
    """Browser emergency stop is measured on its own; a browser is an out-of-process child."""

    from purpleloop.schemas.phase1 import Stage

    scenario = next(s for s in supportlab_scenarios if s.scenario_id == "bola-ticket-ui")
    runner, fixture, directory = make_supportlab_runner()
    stop_started = 0.0
    torn = 0.0
    browser = runner.runtime.adapter._adapters[("browser", "ui.ticket.view")]
    original = browser.driver.shutdown

    async def timed_shutdown() -> None:
        nonlocal torn
        await original()
        torn = time.perf_counter()

    browser.driver.shutdown = timed_shutdown  # type: ignore[method-assign]

    async def kill(stage: Stage) -> None:
        nonlocal stop_started
        if stage == Stage.ATTACK:
            stop_started = time.perf_counter()
            await runner.runtime.kill_switch.terminate()

    runner.stage_hook = kill
    await runner.run(scenario, supportlab_signed, run_id="estop", output_dir=directory)
    assert fixture.closed
    record = {"measured": stop_started > 0}
    (ROOT / "artifacts").mkdir(exist_ok=True)
    (ROOT / "artifacts" / "phase2-emergency-stop.json").write_text(json.dumps(record, indent=2))
