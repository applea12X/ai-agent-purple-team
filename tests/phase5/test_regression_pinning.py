"""WP5.0.10 -- one pinning test per accepted finding, so a regression names its own finding.

Phase 4 pinned all 48 findings to three corpus-level tests; when one failed, the
critical-regression gate could only say "one of these 25 regressed". Here each corpus scenario
gets its own node id, ``test_pinned_finding[<scenario_id>]``, asserting for that one scenario
what its lane's corpus test asserts (``tests/phase1/test_loop.py::test_all_five_paired_loops``,
``tests/phase2/test_supportlab_loop.py::test_full_corpus_paired_loops``,
``tests/phase3/test_agent_corpus.py::test_corpus_metrics_over_the_whole_agent_corpus``), plus
the recorded outcome in ``baselines/regression-outcomes.json``. The corpus tests are unchanged
and still run; the registry names both, most specific first.

Each scenario runs once here. The summaries are kept for the rest of this module, so the
corpus-level aggregates (recall, false-positive rate, cross-surface agreement) are re-checked
over the same runs without running anything twice.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from purpleloop.fixture.app import CANARY
from purpleloop.reporting.bundle import verify_bundle
from purpleloop.reporting.gates import critical_regression_gate, outcomes_from_junit
from purpleloop.runtime.demo import ROOT
from purpleloop.runtime.pinning import (
    LANES,
    PHASE1_CONTROL,
    PHASE1_CUSTOMER,
    SUPPORTLAB_CONTROL,
    Lane,
    PinnedScenario,
    lane_directory,
    load_outcomes,
    outcome_of,
    pinned_scenarios,
    run_pinned,
)
from purpleloop.runtime.supportlab import ALL_CANARIES
from purpleloop.schemas.event import EventKind
from purpleloop.schemas.phase1 import RunSummary, load_ground_truth
from purpleloop.schemas.phase4 import RegressionEntry, RegressionRegistry
from purpleloop.scoring.phase1 import corpus_metrics
from purpleloop.scoring.phase2 import cross_surface_agreement

REGISTRY_PATH = ROOT / "scenarios" / "regression-registry.json"
THIS_FILE = "tests/phase5/test_regression_pinning.py"
PINNED = pinned_scenarios()
RECORDED = load_outcomes().by_scenario()

# Summaries from the per-scenario runs above, reused by the lane aggregates below.
_RUNS: dict[str, RunSummary] = {}

SECRETS: dict[Lane, tuple[str, ...]] = {
    "phase1": (CANARY, PHASE1_CUSTOMER, PHASE1_CONTROL),
    "supportlab": (SUPPORTLAB_CONTROL, *ALL_CANARIES),
    "agent": (SUPPORTLAB_CONTROL, *ALL_CANARIES),
}


def registry() -> RegressionRegistry:
    return RegressionRegistry.model_validate_json(REGISTRY_PATH.read_text())


def exported_text(directory: Path) -> str:
    return "\n".join(
        p.read_text(errors="ignore")
        for p in directory.rglob("*")
        if p.is_file() and p.suffix not in {".png", ".zip"}
    )


# --- the pinning tests ------------------------------------------------------------------------


@pytest.mark.parametrize("pinned", PINNED, ids=[p.scenario_id for p in PINNED])
async def test_pinned_finding(pinned: PinnedScenario, tmp_path: Path) -> None:
    run = await run_pinned(pinned, tmp_path / pinned.scenario_id)
    result = run.summary
    sid = pinned.scenario_id

    # The paired loop: the seeded attack lands at baseline, the defense is credited on replay,
    # and the legitimate task still works on both legs.
    assert result.status == "passed", (sid, result.status, result.reason)
    assert result.baseline is not None and result.replay is not None
    assert result.baseline.security.verdict == "true", sid
    assert result.replay.security.verdict == "false", sid
    assert result.baseline.utility.verdict == result.replay.utility.verdict == "true", sid
    assert result.baseline.seed_hash == result.replay.seed_hash, sid
    assert result.mitigation_effective and result.teardown_complete and run.fixture.closed, sid
    assert result.replay.unauthorized_side_effects == 0, sid

    # The ground-truth label for this one scenario, scored the way corpus_metrics scores it.
    truth = load_ground_truth(lane_directory(pinned.lane) / "ground-truth.json").case(sid)
    assert len(result.findings) == truth.expected_findings, sid
    assert int(result.replay.security.verdict == "true") == truth.expected_negative_findings

    # The recorded outcome: verdicts, finding count, and the run-independent oracle hash.
    assert outcome_of(pinned.lane, result) == RECORDED[sid], (
        f"{sid} moved from its recorded outcome; if deliberate, re-pin with "
        "scripts/repin_regression_outcomes.py in a reviewed commit"
    )

    # Lane-specific facts the corpus tests assert.
    if pinned.lane == "phase1" and "injection" in sid:
        assert result.baseline.susceptible and result.replay.susceptible
    if pinned.lane == "supportlab":
        assert result.lane == "supportlab"
        assert result.evidence_completeness is not None
        assert result.evidence_completeness.completeness == 1.0
        assert result.resources is not None
        for dimension in ("requests", "records", "browser_contexts"):
            assert result.resources.within_tolerance[dimension], (sid, dimension)

    # Evidence: the bundle verifies, no planted secret reaches it, every completed action
    # was preceded by a permit for the same action digest, and no budget is left open.
    verify_bundle(run.directory, allow_partial=True)
    exported = exported_text(run.directory)
    for secret in SECRETS[pinned.lane]:
        assert secret not in exported, sid
    events = run.runner.runtime.ledger.verify()
    for event in events:
        if event.kind == EventKind.RESULT and event.reason_code == "COMPLETED":
            assert any(
                p.action_digest == event.action_digest
                and p.kind == EventKind.POLICY
                and p.decision == "permit"
                for p in events[: event.sequence]
            ), sid
    assert run.runner.runtime.budgets.active == 0, sid
    _RUNS[sid] = result


@pytest.mark.parametrize("lane", LANES)
async def test_lane_aggregates_over_the_pinned_runs(lane: Lane, tmp_path: Path) -> None:
    """The corpus tests' aggregate assertions, over the runs the pinning tests already made.

    A scenario whose pinning test was deselected or failed before recording is run here, so the
    aggregate never silently shrinks to the runs that happened to be cached.
    """
    lane_scenarios = [p for p in PINNED if p.lane == lane]
    summaries = []
    for pinned in lane_scenarios:
        if pinned.scenario_id not in _RUNS:
            run = await run_pinned(pinned, tmp_path / pinned.scenario_id)
            _RUNS[pinned.scenario_id] = run.summary
        summaries.append(_RUNS[pinned.scenario_id])
    metrics = corpus_metrics(
        load_ground_truth(lane_directory(lane) / "ground-truth.json"), summaries
    )
    assert metrics["seeded_recall"] == 1.0, metrics
    assert metrics["false_positives"] == 0 and metrics["false_positive_rate"] == 0.0, metrics
    assert metrics["unevaluated_scenarios"] == [] and metrics["missing_negative_controls"] == []
    assert metrics["negative_control_runs"] == len(lane_scenarios)
    if lane == "supportlab":
        agreement = cross_surface_agreement([p.scenario for p in lane_scenarios], summaries)
        assert agreement["disagreements"] == []
        assert agreement["paired_groups"] >= 2
        assert agreement["agreed_groups"] == agreement["paired_groups"]


# --- the registry points at these tests, one each ---------------------------------------------


def test_recorded_outcomes_cover_exactly_the_corpus() -> None:
    assert set(RECORDED) == {p.scenario_id for p in PINNED}
    assert len(PINNED) == 48


def test_every_finding_names_its_own_pinning_test() -> None:
    entries = registry().covered()
    assert len(entries) == 48
    assert len({entry.test for entry in entries}) == len(entries), "two findings share a test"
    for entry in entries:
        assert entry.test == f"{THIS_FILE}::test_pinned_finding[{entry.scenario_id}]", entry
        assert entry.corpus_test is not None and "[" not in entry.corpus_test, entry


@pytest.fixture(scope="module")
def collected_node_ids() -> set[str]:
    """Node ids pytest itself collects from every file the registry references.

    Asking pytest is the only check that understands parametrized ids exactly as the JUnit
    report will spell them; a regex over the source can confirm the function exists, not that
    ``[param]`` names one of its cases.
    """
    files = sorted(
        {
            test.partition("::")[0]
            for entry in registry().covered()
            for test in entry.pinning_tests()
        }
    )
    completed = subprocess.run(  # noqa: S603 -- fixed argv, the interpreter running this suite
        [
            sys.executable,
            "-m",
            "pytest",
            "--collect-only",
            "-q",
            "--no-cov",
            "-p",
            "no:cacheprovider",
            *files,
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    return {line.strip() for line in completed.stdout.splitlines() if "::" in line}


def test_no_registry_reference_dangles_at_parameter_granularity(
    collected_node_ids: set[str],
) -> None:
    for entry in registry().covered():
        for test in entry.pinning_tests():
            assert test in collected_node_ids, f"{entry.finding_class}: {test} is not collected"


def test_a_bad_parameter_id_is_detected(collected_node_ids: set[str]) -> None:
    """The function-level check accepts a misspelt case; the collected-id check refuses it."""
    bad = f"{THIS_FILE}::test_pinned_finding[agent-indirect-tickte]"
    function = bad.partition("::")[2].split("[")[0]
    source = (ROOT / THIS_FILE).read_text()
    # What a function-name check sees: the function exists, so it would pass.
    assert re.search(rf"^(async )?def {re.escape(function)}\(", source, re.MULTILINE)
    # What the collected-id check sees.
    assert bad not in collected_node_ids
    # And the gate: a dangling id never appears in a report, so it blocks as not-run.
    entry = RegressionEntry(
        finding_class="agent-indirect-ticket",
        scenario_id="agent-indirect-ticket",
        test=bad,
        status="covered",
    )
    passing = dict.fromkeys(collected_node_ids, True)
    decision = critical_regression_gate(RegressionRegistry(entries=(entry,)), passing)
    assert decision.blocked and decision.reason_code == "REGISTRY_TEST_NOT_RUN"


# --- the gate at per-scenario granularity -----------------------------------------------------


def junit(path: Path, results: dict[str, bool]) -> Path:
    """A JUnit report in pytest's own spelling: dotted classname, bracketed parameter."""
    cases = []
    for node, passed in results.items():
        module, _, name = node.partition("::")
        classname = module.removesuffix(".py").replace("/", ".")
        body = "" if passed else '<failure message="injected"/>'
        cases.append(f'<testcase classname="{classname}" name="{name}">{body}</testcase>')
    path.write_text(
        '<?xml version="1.0" encoding="utf-8"?><testsuites><testsuite name="pytest">'
        + "".join(cases)
        + "</testsuite></testsuites>"
    )
    return path


def per_scenario_ids() -> list[str]:
    return [entry.test for entry in registry().covered()]


def corpus_ids() -> list[str]:
    return sorted({str(entry.corpus_test) for entry in registry().covered()})


def test_gate_passes_a_report_of_the_per_scenario_tests(tmp_path: Path) -> None:
    report = junit(tmp_path / "junit.xml", dict.fromkeys(per_scenario_ids(), True))
    decision = critical_regression_gate(registry(), outcomes_from_junit(report))
    assert not decision.blocked and decision.reason_code == "REGISTRY_TESTS_PASSED"


@pytest.mark.parametrize("victim", ["bola", "bola-ticket-ui", "agent-indirect-ticket"])
def test_one_failed_scenario_names_exactly_one_finding(victim: str, tmp_path: Path) -> None:
    results: dict[str, Any] = dict.fromkeys([*per_scenario_ids(), *corpus_ids()], True)
    results[f"{THIS_FILE}::test_pinned_finding[{victim}]"] = False
    decision = critical_regression_gate(
        registry(), outcomes_from_junit(junit(tmp_path / "junit.xml", results))
    )
    assert decision.blocked and decision.reason_code == "REGISTRY_TEST_FAILED"
    assert decision.detail == f"failed pinning tests for: {victim}"


def test_a_failed_corpus_test_still_blocks_every_finding_it_pins(tmp_path: Path) -> None:
    results = dict.fromkeys([*per_scenario_ids(), *corpus_ids()], True)
    results["tests/phase1/test_loop.py::test_all_five_paired_loops"] = False
    decision = critical_regression_gate(
        registry(), outcomes_from_junit(junit(tmp_path / "junit.xml", results))
    )
    assert decision.blocked and decision.reason_code == "REGISTRY_TEST_FAILED"
    named = decision.detail.removeprefix("failed pinning tests for: ").split(", ")
    assert named == ["bola", "direct-injection", "indirect-injection", "mass-assignment", "refund"]


def test_a_corpus_only_report_is_still_judged(tmp_path: Path) -> None:
    """A lane that runs only the three corpus tests (the Phase 4 report shape) still passes."""
    report = junit(tmp_path / "junit.xml", dict.fromkeys(corpus_ids(), True))
    decision = critical_regression_gate(registry(), outcomes_from_junit(report))
    assert not decision.blocked


def test_a_skipped_per_scenario_test_blocks(tmp_path: Path) -> None:
    outcomes = dict.fromkeys(per_scenario_ids(), True)
    outcomes[f"{THIS_FILE}::test_pinned_finding[refund]"] = False  # how JUnit records a skip
    decision = critical_regression_gate(registry(), outcomes)
    assert decision.blocked and decision.detail.endswith(": refund")


def test_a_report_without_any_pinning_test_blocks_as_not_run() -> None:
    decision = critical_regression_gate(registry(), {"tests/other.py::test_x": True})
    assert decision.blocked and decision.reason_code == "REGISTRY_TEST_NOT_RUN"


def test_a_corpus_test_must_be_a_node_id() -> None:
    with pytest.raises(ValueError, match="node id"):
        RegressionEntry(
            finding_class="bola",
            scenario_id="bola",
            test=f"{THIS_FILE}::test_pinned_finding[bola]",
            corpus_test="tests/phase1/test_loop.py",
            status="covered",
        )
