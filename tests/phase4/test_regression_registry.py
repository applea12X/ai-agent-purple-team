"""The committed regression registry: every accepted finding maps to a real pinning test."""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from purpleloop.runtime.demo import ROOT
from purpleloop.schemas.phase4 import RegressionRegistry

REGISTRY_PATH = ROOT / "scenarios" / "regression-registry.json"

LANES = ("phase1", "supportlab", "agent")


def load() -> RegressionRegistry:
    return RegressionRegistry.model_validate_json(REGISTRY_PATH.read_text())


def corpus_scenario_ids() -> set[str]:
    ids: set[str] = set()
    for lane in LANES:
        for path in sorted((ROOT / "scenarios" / lane).glob("*.yaml")):
            if path.name == "oracles.yaml":
                continue
            ids.add(str(yaml.safe_load(path.read_text())["scenario_id"]))
    return ids


def test_registry_covers_every_corpus_scenario() -> None:
    registry = load()
    assert {entry.scenario_id for entry in registry.entries} == corpus_scenario_ids()


def test_no_dangling_test_references() -> None:
    """Every covered entry's pytest node id names a file that exists and a test defined in it."""
    for entry in load().covered():
        file_part, _, function = entry.test.partition("::")
        path = ROOT / file_part
        assert path.exists(), f"{entry.finding_class}: missing test file {file_part}"
        function_name = function.split("[")[0]
        pattern = re.compile(rf"^(async )?def {re.escape(function_name)}\(", re.MULTILINE)
        assert pattern.search(path.read_text()), (
            f"{entry.finding_class}: {function_name} is not defined in {file_part}"
        )


def test_registry_coverage_meets_the_phase4_checkpoint() -> None:
    registry = load()
    assert registry.coverage >= 0.8, f"coverage {registry.coverage:.3f} below the 80% checkpoint"


def test_retired_entries_carry_reasons() -> None:
    for entry in load().entries:
        if entry.status != "covered":
            assert entry.reason, entry.finding_class


def test_registry_file_round_trips(tmp_path: Path) -> None:
    registry = load()
    reloaded = RegressionRegistry.model_validate_json(registry.model_dump_json())
    assert reloaded == registry
