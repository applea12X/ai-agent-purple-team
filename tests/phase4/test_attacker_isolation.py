"""Adaptive-attacker probes cannot move a binding verdict (ADR 0009, found in Phase 4 acceptance).

Before this fix the runner executed the bounded attacker's proposals inside the attack stage,
before the scored snapshot. Their writes reached the security oracle's state, their responses
reached its input, and their telemetry reached the unauthorized-side-effect count. On
``agent-indirect-markdown`` that turned an effective defense into a reported regression, and
across the corpus it put attacker writes into 22 of 25 defended replays -- an advisory component
deciding binding numbers. These tests fail when the probes are moved back before scoring.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

from purpleloop.control.attacker import BoundedAttacker
from purpleloop.runtime.runner import PurpleTeamRunner
from purpleloop.runtime.supportlab import InProcessSupportlab
from purpleloop.schemas.authorization import AuthorizationManifest
from purpleloop.schemas.phase1 import LegResult, Phase1Scenario

Make = Callable[..., tuple[PurpleTeamRunner, InProcessSupportlab, Path]]

BOUNDARY = "ADVISORY_PROBES_AFTER_BINDING"


def binding_view(leg: LegResult | None) -> dict[str, Any]:
    """Every binding measurement of a leg, without per-run evidence identifiers."""
    assert leg is not None
    return {
        "security": (leg.security.verdict, leg.security.observed),
        "utility": (leg.utility.verdict, leg.utility.observed),
        "utility_under_attack": (
            (leg.utility_under_attack.verdict, leg.utility_under_attack.observed)
            if leg.utility_under_attack is not None
            else None
        ),
        "susceptible": leg.susceptible,
        "unauthorized_side_effects": leg.unauthorized_side_effects,
        "detectors": [(d.rule_id, d.expected, d.observed, d.time_to_detect) for d in leg.detectors],
        "seed_hash": leg.seed_hash,
    }


def ledger(directory: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in (directory / "evidence.jsonl").read_text().splitlines()]


async def test_attacker_probes_leave_every_binding_measurement_unchanged(
    make_agent_runner: Make,
    agent_scenarios: list[Phase1Scenario],
    agent_manifest: AuthorizationManifest,
    demo_attacker: Callable[[], BoundedAttacker],
) -> None:
    scenario = next(s for s in agent_scenarios if s.scenario_id == "agent-indirect-markdown")
    plain_runner, _, plain_dir = make_agent_runner()
    plain = await plain_runner.run(scenario, agent_manifest, run_id="plain", output_dir=plain_dir)
    probed_runner, _, probed_dir = make_agent_runner(attacker=demo_attacker())
    probed = await probed_runner.run(
        scenario, agent_manifest, run_id="probed", output_dir=probed_dir
    )

    assert plain.status == "passed", plain.reason
    assert probed.status == "passed", probed.reason
    assert probed.mitigation_effective and not probed.utility_regression
    for leg in ("baseline", "replay"):
        assert binding_view(getattr(probed, leg)) == binding_view(getattr(plain, leg)), leg
    assert probed.replay is not None and probed.replay.unauthorized_side_effects == 0
    assert [f.observed_impact for f in probed.findings] == [
        f.observed_impact for f in plain.findings
    ]


async def test_probes_still_execute_and_are_recorded_after_the_boundary(
    make_agent_runner: Make,
    agent_scenarios: list[Phase1Scenario],
    agent_manifest: AuthorizationManifest,
    demo_attacker: Callable[[], BoundedAttacker],
) -> None:
    """The fix moves the probes; it does not stop them exercising the kernel."""
    scenario = next(s for s in agent_scenarios if s.scenario_id == "agent-indirect-markdown")
    runner, _, directory = make_agent_runner(attacker=demo_attacker())
    summary = await runner.run(scenario, agent_manifest, run_id="probed", output_dir=directory)

    assert any(p.accepted for p in summary.proposals), "no probe compiled"
    assert any(not p.accepted for p in summary.proposals), "no probe was refused"
    events = ledger(directory)
    boundaries = [e["sequence"] for e in events if e["reason_code"] == BOUNDARY]
    scored = [
        e["sequence"]
        for e in events
        if e["kind"] == "oracle" and e["reason_code"] in {"BASELINE_SCORED", "REPLAY_SCORED"}
    ]
    assert len(boundaries) == 2 and len(scored) == 2
    # Each leg's boundary comes after that leg's binding score.
    assert scored[0] < boundaries[0] < scored[1] < boundaries[1]
    proposal_sequences = [e["sequence"] for e in events if e["kind"] == "proposal"]
    assert proposal_sequences
    for sequence in proposal_sequences:
        leg_boundary = (
            max(b for b in boundaries if b < sequence)
            if any(b < sequence for b in boundaries)
            else None
        )
        assert leg_boundary is not None, f"proposal at {sequence} ran before any boundary"
    # Accepted probes reached the fixture: CRM writes executed after the baseline boundary.
    executed_after = [
        e
        for e in events
        if e["kind"] == "result"
        and e["decision"] == "permit"
        and e["sequence"] > boundaries[0]
        and e.get("stage") == "detect"
    ]
    assert executed_after, "no accepted probe executed"


async def test_the_whole_corpus_passes_with_the_attacker_on(
    make_agent_runner: Make,
    agent_scenarios: list[Phase1Scenario],
    agent_manifest: AuthorizationManifest,
    demo_attacker: Callable[[], BoundedAttacker],
) -> None:
    """The configuration agent-demo actually runs: 25 of 25, and zero defended side effects."""
    failures: list[tuple[str, str, int]] = []
    for index, scenario in enumerate(agent_scenarios):
        runner, _, directory = make_agent_runner(attacker=demo_attacker())
        summary = await runner.run(
            scenario, agent_manifest, run_id=f"corpus-{index}", output_dir=directory
        )
        assert summary.proposals, scenario.scenario_id
        side_effects = summary.replay.unauthorized_side_effects if summary.replay else -1
        if summary.status != "passed" or side_effects != 0:
            failures.append((scenario.scenario_id, summary.status, side_effects))
    assert not failures, failures
