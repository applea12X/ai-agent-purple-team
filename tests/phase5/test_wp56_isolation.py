"""WP5.6.4 -- the benchmark subset stays out of the holdout set and every tuning path.

``tests/phase4/test_holdout.py`` greps the package so that nothing outside the holdout executor
reads the holdout directory. This extends the same mechanism to the benchmark directories, in
both directions: no source module except the benchmark runtime names them, no tuning,
calibration, baseline, or holdout input names a benchmark case, and the authored corpus's
loaders cannot pick one up.
"""

from __future__ import annotations

import json
import re

from purpleloop.runtime.benchmark import BENCHMARK_ROOT, IMPORTED_ROOT, SUBSET_DIR
from purpleloop.runtime.demo import ROOT
from purpleloop.schemas.phase1 import load_scenario, scenario_paths

SRC = ROOT / "src" / "purpleloop"
#: A source line that names a benchmark directory as a path.
BENCHMARK_PATH = re.compile(
    r"""["']scenarios["']\s*/\s*["'](benchmark|imported)["']"""
    r"""|scenarios/(benchmark|imported)|["']agentdojo-style["']"""
)
AUTHORED_LANES = ("phase1", "supportlab", "agent")
#: Every file a tuning, calibration, gating, or held-out path reads.
GUARDED_INPUTS = (
    "scenarios/holdout/mutations.json",
    "scenarios/smoke.json",
    "scenarios/regression-registry.json",
    "scenarios/evaluator-redteam/cases.json",
    "scenarios/agent/ground-truth.json",
    "scenarios/supportlab/ground-truth.json",
    "scenarios/phase1/ground-truth.json",
)


def subset_ids() -> set[str]:
    raw = json.loads((SUBSET_DIR / "provenance.json").read_text())
    return set(raw["case_ids"])


def test_only_the_benchmark_runtime_names_the_benchmark_directories() -> None:
    offenders = [
        path.relative_to(SRC).as_posix()
        for path in sorted(SRC.rglob("*.py"))
        if BENCHMARK_PATH.search(path.read_text())
        and path.relative_to(SRC).as_posix() != "runtime/benchmark.py"
    ]
    assert not offenders, offenders
    assert SUBSET_DIR.parent == BENCHMARK_ROOT == ROOT / "scenarios" / "benchmark"
    assert IMPORTED_ROOT == ROOT / "scenarios" / "imported"


def test_only_the_benchmark_cli_and_fixture_import_the_benchmark_modules() -> None:
    allowed = {
        "purpleloop.runtime.benchmark": {"benchmark_cli.py"},
        "purpleloop.control.benchmark_tools": {
            "runtime/benchmark.py",
            "fixture/supportlab/app.py",
        },
        "purpleloop.benchmark_cli": {"phase5_cli.py"},
    }
    for module, importers in allowed.items():
        pattern = re.compile(
            rf"^\s*(from {re.escape(module)} import|import {re.escape(module)})", re.M
        )
        found = {
            path.relative_to(SRC).as_posix()
            for path in SRC.rglob("*.py")
            if pattern.search(path.read_text())
        }
        assert found == importers, (module, sorted(found))


def test_no_tuning_calibration_or_holdout_input_names_a_benchmark_case() -> None:
    ids = subset_ids()
    inputs = [ROOT / name for name in GUARDED_INPUTS if (ROOT / name).exists()]
    inputs.extend(sorted((ROOT / "baselines").glob("*.json")))
    inputs.extend(sorted((ROOT / "scenarios" / "holdout").rglob("*")))
    assert len(inputs) > 8, "the guarded inputs moved; update this test"
    for path in inputs:
        if not path.is_file():
            continue
        text = path.read_text()
        assert "agentdojo-style" not in text, path
        leaked = sorted(sid for sid in ids if sid in text)
        assert not leaked, (path, leaked)


def test_benchmark_ids_are_disjoint_from_every_authored_lane_and_the_holdout_set() -> None:
    ids = subset_ids()
    authored = {
        load_scenario(path).scenario_id
        for lane in AUTHORED_LANES
        for path in scenario_paths(ROOT / "scenarios" / lane)
    }
    assert len(authored) == 48
    assert not ids & authored
    holdout = json.loads((ROOT / "scenarios" / "holdout" / "mutations.json").read_text())
    assert not ids & {case["case_id"] for case in holdout["cases"]}
    # Every benchmark case carries the ``ads-`` prefix, so a stray reference is greppable.
    assert all(sid.startswith("ads-") for sid in ids)


def test_the_authored_corpus_loaders_cannot_reach_the_subset() -> None:
    from purpleloop.agent_cli import SCENARIOS
    from purpleloop.runtime.pinning import LANES

    assert SCENARIOS == ROOT / "scenarios" / "agent"
    assert set(LANES) == set(AUTHORED_LANES)
    for lane in AUTHORED_LANES:
        names = {path.name for path in scenario_paths(ROOT / "scenarios" / lane)}
        assert not any(name.startswith("ads-") for name in names), lane


def test_the_new_modules_do_not_reference_the_holdout_set() -> None:
    """Restates the Phase 4 rule for the files this package adds, so a regression names them."""
    for relative in ("runtime/benchmark.py", "benchmark_cli.py", "control/benchmark_tools.py"):
        assert "holdout" not in (SRC / relative).read_text(), relative


def test_the_path_grep_can_fail() -> None:
    """The pattern matches the one module allowed to name the directories, so it is not vacuous."""
    assert BENCHMARK_PATH.search((SRC / "runtime" / "benchmark.py").read_text())
    assert BENCHMARK_PATH.search('SUBSET = ROOT / "scenarios" / "benchmark" / "x"')
    assert BENCHMARK_PATH.search("open('scenarios/imported/agentdojo/a.yaml')")
    assert not BENCHMARK_PATH.search('ROOT / "scenarios" / "agent"')
