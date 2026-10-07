"""The adaptive attacker probes; it must not contaminate what the scenario's oracles score.

Found by CI, on a scenario that passes without the attacker and regressed with it. The attacker's
accepted proposals wrote rows into the same table the scenario's security oracle counts, so the
defended replay still scored "true" and the defense was never credited -- even though the defense
had in fact stopped the injected intent. The same reasoning applies to detectors: an attacker
write firing a telemetry rule inside the defended replay is a false detector signal.

The fix is ordering, not suppression: proposals still run, under the same defense configuration,
charged to the same budget, with every decision recorded -- but after the leg's state and
telemetry have been captured and scored.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pytest

from purpleloop.control.attacker import BoundedAttacker
from purpleloop.runtime.runner import PurpleTeamRunner
from purpleloop.runtime.supportlab import InProcessSupportlab
from purpleloop.schemas.authorization import AuthorizationManifest
from purpleloop.schemas.phase1 import Phase1Scenario

Make = Callable[..., tuple[PurpleTeamRunner, InProcessSupportlab, Path]]

#: The scenario CI caught: its security oracle counts crm_records, which the attacker also writes.
CONTAMINATED = "agent-indirect-markdown"


def attacker() -> BoundedAttacker:
    return BoundedAttacker(
        max_proposals=8,
        max_depth=3,
        operations=["crm.update", "email.send", "export.create"],
        own_tenant="org-a",
        other_tenants=("org-b",),
        resource_id="admin-a",
    )


@pytest.mark.parametrize("scenario_id", [CONTAMINATED, "agent-confused-deputy"])
async def test_the_attacker_does_not_change_a_scenario_verdict(
    make_agent_runner: Make,
    agent_scenarios: list[Phase1Scenario],
    agent_manifest: AuthorizationManifest,
    scenario_id: str,
) -> None:
    """The same scenario reaches the same verdict with the attacker on and off."""
    scenario = next(s for s in agent_scenarios if s.scenario_id == scenario_id)

    runner, _, directory = make_agent_runner()
    without = await runner.run(scenario, agent_manifest, run_id="no-attacker", output_dir=directory)

    runner, _, directory = make_agent_runner(attacker=attacker())
    with_attacker = await runner.run(
        scenario, agent_manifest, run_id="with-attacker", output_dir=directory
    )

    assert without.status == "passed", without.reason
    assert with_attacker.status == without.status, with_attacker.reason
    assert with_attacker.mitigation_effective == without.mitigation_effective
    assert with_attacker.baseline is not None and with_attacker.replay is not None
    assert with_attacker.baseline.security.verdict == "true"
    assert with_attacker.replay.security.verdict == "false"

    # The attacker really did run: this passes by ordering, not by disabling the probe.
    accepted = [p for p in with_attacker.proposals if p.accepted]
    assert accepted, "no proposal was accepted; the test would pass vacuously"
    assert any(not p.accepted for p in with_attacker.proposals), "no refusal was recorded"


async def test_the_attacker_does_not_create_detector_signal_in_the_scored_window(
    make_agent_runner: Make,
    agent_scenarios: list[Phase1Scenario],
    agent_manifest: AuthorizationManifest,
) -> None:
    """An attacker write must not make a defended replay look detected."""
    scenario = next(s for s in agent_scenarios if s.scenario_id == CONTAMINATED)

    runner, _, directory = make_agent_runner()
    without = await runner.run(scenario, agent_manifest, run_id="det-off", output_dir=directory)
    runner, _, directory = make_agent_runner(attacker=attacker())
    with_attacker = await runner.run(
        scenario, agent_manifest, run_id="det-on", output_dir=directory
    )

    def observed(summary: object, leg: str) -> set[str]:
        result = getattr(summary, leg)
        return {d.rule_id for d in result.detectors if d.observed}

    for leg in ("baseline", "replay"):
        assert observed(with_attacker, leg) == observed(without, leg), leg


async def test_proposal_side_effects_are_excluded_from_the_scored_state(
    make_agent_runner: Make,
    agent_scenarios: list[Phase1Scenario],
    agent_manifest: AuthorizationManifest,
) -> None:
    """The scored snapshot reflects the scenario's own attack, not the probe that followed it."""
    scenario = next(s for s in agent_scenarios if s.scenario_id == CONTAMINATED)
    runner, _, directory = make_agent_runner(attacker=attacker())
    summary = await runner.run(scenario, agent_manifest, run_id="scope", output_dir=directory)

    assert summary.replay is not None
    # The defended replay's scored state has no crm rows at all: the injected intent was stopped,
    # and the attacker's own writes landed after the snapshot that the oracle reads.
    rows = summary.replay.security.observed
    assert rows in (None, [], 0), rows
