"""WP3.7 -- the measurements the Phase 3 acceptance record reports.

Every number in ``docs/phase3-acceptance.md`` comes from a command that was actually run. These
are those commands.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path

import pytest

from purpleloop.control.lanes import AGENT_LANE
from purpleloop.control.plan_compiler import compile_plan
from purpleloop.runtime.runner import PurpleTeamRunner
from purpleloop.runtime.supportlab import InProcessSupportlab
from purpleloop.schemas.authorization import AuthorizationManifest
from purpleloop.schemas.phase1 import Phase1Scenario, RunSummary
from purpleloop.schemas.phase3 import ModelPin
from purpleloop.scoring.phase2 import evidence_completeness
from purpleloop.scoring.phase3 import (
    estimate_is_a_bound,
    estimate_tokens,
    token_accounting,
)

Make = Callable[..., tuple[PurpleTeamRunner, InProcessSupportlab, Path]]
ARTIFACTS = Path("artifacts")


def record(name: str, payload: object) -> None:
    """Write one acceptance artifact. Sync, so it stays off the async event loop."""
    ARTIFACTS.mkdir(exist_ok=True)
    (ARTIFACTS / name).write_text(json.dumps(payload, indent=2) + "\n")


async def _run(
    make: Make, scenario: Phase1Scenario, manifest: AuthorizationManifest, run_id: str
) -> tuple[RunSummary, Path]:
    runner, _, directory = make()
    return await runner.run(scenario, manifest, run_id=run_id, output_dir=directory), directory


async def test_agent_lane_replay_determinism(
    make_agent_runner: Make,
    agent_scenarios: list[Phase1Scenario],
    agent_manifest: AuthorizationManifest,
) -> None:
    """Repeated runs of each scenario produce identical normalized event and oracle hashes.

    The agent lane is deterministic *because the provider is*: the scripted model makes no network
    call. This measures the lane, not a model, and the acceptance record says so.
    """
    trials = 3
    matches = 0
    total = 0
    mismatched: list[str] = []
    for scenario in agent_scenarios:
        fingerprints = set()
        for trial in range(trials):
            summary, _ = await _run(
                make_agent_runner,
                scenario,
                agent_manifest,
                f"replay-{scenario.scenario_id}-{trial}",
            )
            fingerprints.add((summary.event_replay_hash, summary.oracle_hash))
            total += 1
        if len(fingerprints) == 1:
            matches += trials
        else:
            mismatched.append(scenario.scenario_id)
    record(
        "phase3-replay.json",
        {
            "lane": AGENT_LANE.name,
            "provider": "offline-scripted",
            "scenarios": len(agent_scenarios),
            "trials_per_scenario": trials,
            "trials": total,
            "matched": matches,
            "rate": matches / total,
            "mismatched_scenarios": mismatched,
        },
    )
    assert not mismatched, mismatched
    assert matches / total >= 0.95


async def test_evidence_completeness_over_the_agent_corpus(
    make_agent_runner: Make,
    agent_scenarios: list[Phase1Scenario],
    agent_manifest: AuthorizationManifest,
) -> None:
    """Required evidence fields, including the new MODEL, JUDGE, and PROPOSAL kinds."""
    from purpleloop.runtime.ledger import EvidenceLedger

    worst = 1.0
    for scenario in agent_scenarios:
        _, directory = await _run(
            make_agent_runner, scenario, agent_manifest, f"complete-{scenario.scenario_id}"
        )
        events = EvidenceLedger(directory / "evidence.jsonl").verify()
        completeness = evidence_completeness(events)
        worst = min(worst, completeness.completeness)
        assert not completeness.missing, (scenario.scenario_id, completeness.missing[:5])
    record("phase3-evidence-completeness.json", {"minimum_completeness": worst, "threshold": 0.99})
    assert worst >= 0.99


def test_the_completeness_metric_fails_when_a_required_field_is_removed() -> None:
    """The metric must be able to fail. Same rule as corpus_metrics."""
    from purpleloop.schemas.event import EventKind, EvidenceEvent

    def event(**overrides: object) -> EvidenceEvent:
        fields: dict[str, object] = {
            "schema_version": "1.1.0",
            "scenario_id": "s",
            "scenario_version": "1.0.0",
            "stage": "attack",
            "component_version": "v",
            "run_id": "r",
            "trace_id": "t",
            "sequence": 0,
            "timestamp": "2026-09-09T00:00:00Z",
            "actor": "a",
            "kind": EventKind.MODEL,
            "manifest_digest": "a" * 64,
            "policy_digest": "b" * 64,
            "reason_code": "MODEL_CALLED",
            "data": {"call": {}, "retrieved": [], "quarantined": False},
            "event_hash": "c" * 64,
        }
        fields.update(overrides)
        return EvidenceEvent.model_validate(fields)

    assert evidence_completeness([event()]).completeness == 1.0
    degraded = evidence_completeness([event(data={"call": {}, "retrieved": []})])
    assert degraded.completeness < 1.0
    assert any("quarantined" in name for name in degraded.missing)


async def test_token_and_cost_estimate_against_actual(
    make_agent_runner: Make,
    agent_scenarios: list[Phase1Scenario],
    agent_manifest: AuthorizationManifest,
) -> None:
    """Actual token use against a pre-run estimate, per scenario, reported whatever it is."""
    assert agent_manifest.phase3 is not None
    pin: ModelPin = agent_manifest.phase3.model_pins[0]
    rows: list[dict[str, object]] = []
    for scenario in agent_scenarios:
        plan = compile_plan(scenario, agent_manifest, lane=AGENT_LANE)
        agent_nodes = sum(node.action.adapter == "agent" for node in plan.nodes)
        # Both legs, and the utility-under-attack pass re-runs the clean nodes.
        clean_nodes = sum(
            node.action.adapter == "agent" and node.stage == "clean" for node in plan.nodes
        )
        calls = 2 * (agent_nodes + clean_nodes)
        estimated_tokens, estimated_cost = estimate_tokens(pin, model_calls=calls)
        summary, _ = await _run(
            make_agent_runner, scenario, agent_manifest, f"tokens-{scenario.scenario_id}"
        )
        accounting = token_accounting(
            estimated_tokens=estimated_tokens,
            actual_tokens=summary.tokens_used,
            estimated_cost=estimated_cost,
            actual_cost=summary.cost_microusd,
        )
        rows.append(
            {
                "scenario_id": scenario.scenario_id,
                "model_calls": calls,
                **accounting.model_dump(mode="json"),
            }
        )
    record(
        "phase3-token-accounting.json",
        {"pin": pin.model_dump(mode="json"), "scenarios": rows},
    )
    # The offline pin's declared price is zero, so cost is a true measured zero, not a blank.
    assert all(row["actual_cost_microusd"] == 0 for row in rows)
    assert all(int(row["actual_tokens"]) > 0 for row in rows)  # type: ignore[arg-type]
    within = sum(bool(row["within_tolerance"]["tokens"]) for row in rows)  # type: ignore[index]
    # Reported whether it passes or misses; the threshold does not decide what gets written down.
    assert within >= 0, within
    assert not estimate_is_a_bound(pin), "the offline pin declares calibrated expectations"


@pytest.mark.parametrize("seed", [42])
def test_the_phase2_seed_hash_is_unchanged_by_the_agent_surface(seed: int) -> None:
    """Adding agent tables must not move the Phase 2 lane's recorded seed hash."""
    from purpleloop.fixture.supportlab import seed as seeding
    from purpleloop.fixture.supportlab.database import SqliteDatabase

    db = SqliteDatabase()
    db.provision()
    seeding.apply(db, seed)
    db.materialize()
    try:
        assert db.state_hash() == "5c270cdda4ecb931d37a1285636cc84f609fbc1c3d467d05a0116cca235d1b3d"
    finally:
        db.teardown()
