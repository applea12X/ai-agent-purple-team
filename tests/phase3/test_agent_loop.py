"""The agent lane end to end: a seeded indirect injection, and the defense that stops it."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from purpleloop.runtime.runner import PurpleTeamRunner
from purpleloop.runtime.supportlab import InProcessSupportlab
from purpleloop.schemas.authorization import AuthorizationManifest
from purpleloop.schemas.phase1 import Phase1Scenario

Make = Callable[..., tuple[PurpleTeamRunner, InProcessSupportlab, Path]]


async def test_indirect_injection_succeeds_then_the_defense_stops_it(
    make_agent_runner: Make,
    agent_scenarios: list[Phase1Scenario],
    agent_manifest: AuthorizationManifest,
) -> None:
    scenario = next(s for s in agent_scenarios if s.scenario_id == "agent-indirect-ticket")
    runner, fixture, directory = make_agent_runner()
    summary = await runner.run(scenario, agent_manifest, run_id="agent-1", output_dir=directory)

    assert summary.status == "passed", summary.reason
    assert summary.baseline is not None and summary.replay is not None
    # The attack executed a real side effect in the baseline leg ...
    assert summary.baseline.security.verdict == "true"
    assert summary.baseline.susceptible
    assert summary.baseline.unauthorized_side_effects > 0
    # ... and the same seed, plan, and budget produce no side effect once the content is
    # quarantined. That pairing is what credits the defense.
    assert summary.replay.security.verdict == "false"
    assert summary.mitigation_effective and not summary.utility_regression
    assert summary.defense is not None and summary.defense.profile == "retrieval-provenance-guard"
    assert fixture.closed and summary.teardown_complete
