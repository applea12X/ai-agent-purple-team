"""The named PR-lane smoke set: real, labelled scenarios covering every lane."""

from __future__ import annotations

import json

from purpleloop.runtime.demo import ROOT
from purpleloop.schemas.phase1 import load_ground_truth, load_scenario
from purpleloop.schemas.phase4 import SmokeSet

SMOKE_PATH = ROOT / "scenarios" / "smoke.json"


def load() -> SmokeSet:
    return SmokeSet.model_validate(json.loads(SMOKE_PATH.read_text()))


def test_smoke_set_size_and_lane_coverage() -> None:
    smoke = load()
    assert 10 <= len(smoke.scenarios) <= 20
    lanes = {member.lane for member in smoke.scenarios}
    assert lanes == {"phase1", "supportlab", "agent"}


def test_every_member_exists_is_runnable_and_is_labelled() -> None:
    truths = {
        lane: load_ground_truth(ROOT / "scenarios" / lane / "ground-truth.json")
        for lane in ("phase1", "supportlab", "agent")
    }
    for member in load().scenarios:
        path = ROOT / "scenarios" / member.lane / f"{member.scenario_id}.yaml"
        assert path.exists(), f"{member.scenario_id} does not exist in {member.lane}"
        scenario = load_scenario(path)
        scenario.require_runnable()
        assert scenario.scenario_id == member.scenario_id
        truths[member.lane].case(member.scenario_id)  # raises when unlabelled


def test_smoke_covers_a_browser_surface_scenario() -> None:
    """At least one member exercises the browser path, so the PR lane covers all surfaces."""
    surfaces = set()
    for member in load().scenarios:
        scenario = load_scenario(ROOT / "scenarios" / member.lane / f"{member.scenario_id}.yaml")
        surfaces.add(scenario.effective_surface)
    assert {"api", "agent"} <= surfaces
    assert surfaces & {"browser", "both"}
