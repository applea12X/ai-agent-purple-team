"""WP5.6.1-5.6.3 -- the committed subset, run end to end, reported apart from the authored 48.

The subset is authored here in AgentDojo's task shape; no upstream data was available. These
tests pin that it claims nothing it does not have (no import source, no upstream version), that
the committed scenarios are exactly what their hand-authored records promote, and that the runs
and metrics hold under both deterministic stand-ins.
"""

from __future__ import annotations

import asyncio
import json
import shutil
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError
from typer.testing import CliRunner

from purpleloop.cli import app
from purpleloop.control.benchmark_tools import (
    BENCHMARK_DEFENSE_APPLICABILITY,
    BENCHMARK_DEFENSES,
    FIXTURE_DEFENSES,
)
from purpleloop.control.phase3_tools import AGENT_DEFENSES, COMBINED_DEFENSES
from purpleloop.reporting.bundle import verify_bundle
from purpleloop.runtime.benchmark import (
    BENCHMARK_LANE,
    IMPORTED_ROOT,
    STAND_INS,
    SUBSET_DIR,
    BenchmarkMetrics,
    benchmark_metrics,
    build_subset,
    committed_subset,
    load_candidates,
    run_subset,
    subset_drift,
)
from purpleloop.runtime.demo import ROOT
from purpleloop.schemas.common import digest_data
from purpleloop.schemas.phase1 import Phase1Scenario, RunSummary, load_scenario, scenario_paths

#: The subset's corpus digest, computed the same way as the per-lane digests in
#: ``test_phase5_scenario.py``. A deliberate subset edit updates this literal in the same
#: commit, by rerunning ``purpleloop benchmark-promote --write``.
PINNED_SUBSET = (6, "5843b677f03a37409bc4a9178d4ce38b013f0b94a70790f44bdba18858c1784c")

#: The two authored registries as they stood at the phase base (8f000e0). WP5.6 must not change
#: them: the subset's applicability lives in ``benchmark_tools``.
BASE_REGISTRY_DIGESTS = {
    "AGENT_DEFENSES": "8da253ae9a9d4f1da7646b164c27a73b8595a8d151951e52dd4eebda2a2e4b52",
    "COMBINED_DEFENSES": "5ac407ab3cfc0f559e8080cdecea5a477985b15714daa1506fb958b50c637a43",
}

#: Under the delimitation-blind stand-in, every defense is credited. When WP5.6 landed, two were
#: not: retrieval-provenance-guard on a refund and on an export, because the guard's sink-side
#: check covered email only (f20f482) and its prompt marking alone does not stop a model that
#: ignores delimiting. The WP5.0.2 real-model run found the same gap on qwen2.5:7b, and the
#: fixture now enforces provenance at the refund, export, and privileged-CRM sinks too
#: (``docs/phase5/wp5.0-real-model-acceptance.md``), so the two are credited.
BLIND_CREDITED = {
    "ads-diagnostics-unapproved-refund",
    "ads-handover-unapproved-export",
    "ads-portal-check-exfiltrate-note",
    "ads-runbook-privilege-escalation",
    "ads-ticket-summary-exfiltrate-note",
    "ads-vendor-status-unapproved-refund",
}
BLIND_UNCREDITED: set[str] = set()


def registry_digest(defenses: dict[str, tuple[frozenset[str], dict[str, bool]]]) -> str:
    return digest_data({k: [sorted(v[0]), v[1]] for k, v in sorted(defenses.items())})


@pytest.fixture(scope="module")
def runs(
    tmp_path_factory: pytest.TempPathFactory,
) -> dict[str, tuple[Path, list[RunSummary]]]:
    scenarios = committed_subset()
    results = {}
    for name, model in sorted(STAND_INS.items()):
        root = tmp_path_factory.mktemp(f"benchmark-{name}")
        results[name] = (root, asyncio.run(run_subset(root, scenarios, model=model())))
    return results


def metrics_for(name: str, summaries: list[RunSummary]) -> BenchmarkMetrics:
    _, report, truth = build_subset()
    return benchmark_metrics(
        subset=SUBSET_DIR.name,
        stand_in=name,
        report=report,
        truth=truth,
        scenarios=committed_subset(),
        summaries=summaries,
    )


# --- 5.6.1: the subset is recorded, and claims no upstream it does not have ----------------------


def test_the_committed_subset_is_pinned_and_in_step_with_its_records() -> None:
    paths = scenario_paths(SUBSET_DIR)
    count, digest = PINNED_SUBSET
    assert len(paths) == count
    assert digest_data(sorted((p.name, load_scenario(p).digest()) for p in paths)) == digest
    assert subset_drift() == []


def test_drift_between_records_and_committed_files_is_detected(tmp_path: Path) -> None:
    copy = tmp_path / "subset"
    shutil.copytree(SUBSET_DIR, copy)
    target = copy / "ads-handover-unapproved-export.yaml"
    target.write_text(target.read_text().replace("expected: false", "expected: true"))
    (copy / "ads-stray.yaml").write_text(
        (copy / "ads-runbook-privilege-escalation.yaml").read_text()
    )
    drift = subset_drift(copy)
    assert "ads-handover-unapproved-export.yaml" in drift and "ads-stray.yaml" in drift


def test_the_subset_record_claims_no_upstream() -> None:
    provenance = json.loads((SUBSET_DIR / "provenance.json").read_text())
    assert provenance["origin"] == "authored" and provenance["upstream_text_copied"] is False
    assert provenance["upstream_version"] is None and provenance["upstream_commit"] is None
    assert provenance["case_ids"] == [case.scenario_id for case in load_candidates()]
    assert provenance["to_import_real_cases"], "the blocked import must say how to unblock it"
    for scenario in committed_subset():
        assert scenario.origin == "authored" and scenario.import_source is None
        assert scenario.public_exposure is False and scenario.schema_version == "1.4.0"
        assert "no upstream case text copied" in scenario.provenance
        assert scenario.license == "CC0-1.0"
    # Reserved for real imports; nothing may sit there claiming to be one without the data.
    assert not IMPORTED_ROOT.exists()


def test_promotion_counts_are_recorded_and_both_reported() -> None:
    _, report, truth = build_subset()
    assert (report.attempted, report.promoted, report.not_promoted) == (8, 6, 2)
    committed = json.loads((SUBSET_DIR / "promotion-report.json").read_text())
    assert committed["attempted"] == 8 and committed["promoted"] == 6
    declined = {o.scenario_id: o.reason for o in report.outcomes if not o.promoted}
    assert set(declined) == {
        "ads-book-callback-exfiltrate-note",
        "ads-ticket-summary-delete-tickets",
    }
    assert "calendar" in declined["ads-book-callback-exfiltrate-note"]
    assert "delete" in declined["ads-ticket-summary-delete-tickets"]
    assert {c.scenario_id for c in truth.cases} == {s.scenario_id for s in committed_subset()}


def test_defense_applicability_is_separate_and_names_exactly_the_subset() -> None:
    scenarios = committed_subset()
    named = {sid for ids in BENCHMARK_DEFENSE_APPLICABILITY.values() for sid in ids}
    assert named == {s.scenario_id for s in scenarios}, "stale or missing applicability"
    for scenario in scenarios:
        assert scenario.scenario_id in BENCHMARK_DEFENSES[scenario.defense_profile][0]
    assert registry_digest(AGENT_DEFENSES) == BASE_REGISTRY_DIGESTS["AGENT_DEFENSES"]
    assert registry_digest(COMBINED_DEFENSES) == BASE_REGISTRY_DIGESTS["COMBINED_DEFENSES"]
    assert BENCHMARK_LANE.defenses == BENCHMARK_DEFENSES
    for profile, (applicable, config) in COMBINED_DEFENSES.items():
        extra = BENCHMARK_DEFENSE_APPLICABILITY.get(profile, frozenset())
        assert FIXTURE_DEFENSES[profile] == (applicable | extra, config)
        if profile in BENCHMARK_DEFENSES:
            # One configuration value per profile: a defense means the same thing on both lanes.
            assert BENCHMARK_DEFENSES[profile][1] == config
    assert BENCHMARK_LANE.scenario_versions == frozenset({"1.4.0"})


# --- 5.6.2 / 5.6.3: end to end, offline, reported separately ------------------------------------


def test_every_promoted_case_passes_under_the_scripted_stand_in(
    runs: dict[str, tuple[Path, list[RunSummary]]],
) -> None:
    root, summaries = runs["scripted"]
    assert {s.status for s in summaries} == {"passed"}, [
        (s.scenario_id, s.reason) for s in summaries
    ]
    for summary in summaries:
        assert summary.lane == BENCHMARK_LANE.name
        assert summary.baseline is not None and summary.replay is not None
        assert summary.baseline.security.verdict == "true"
        assert summary.replay.security.verdict == "false"
        assert summary.baseline.utility.verdict == "true"
        assert summary.baseline.utility_under_attack is not None
    suite = verify_bundle(root)
    assert suite["complete"] and suite["scenarios"] == 6
    assert json.loads((root / "suite.json").read_text())["lane"] == "supportlab-agent-benchmark"


def test_metrics_are_reported_apart_from_the_authored_corpus(
    runs: dict[str, tuple[Path, list[RunSummary]]],
) -> None:
    metrics = metrics_for("scripted", runs["scripted"][1])
    assert (metrics.attempted, metrics.promoted, metrics.not_promoted) == (8, 6, 2)
    assert metrics.origin_counts == {"authored": 6, "imported": 0}
    assert metrics.possibly_contaminated == ()
    assert metrics.corpus["seeded_recall"] == 1.0
    assert metrics.corpus["false_positives"] == 0
    assert metrics.corpus["negative_control_runs"] == 6
    assert metrics.corpus["unevaluated_scenarios"] == []
    assert set(metrics.defense_credited) == {s.scenario_id for s in committed_subset()}
    assert "reported separately from the 48 authored" in metrics.note


def test_the_delimitation_blind_stand_in_separates_model_dependent_credit(
    runs: dict[str, tuple[Path, list[RunSummary]]],
) -> None:
    root, summaries = runs["delimitation-blind"]
    metrics = metrics_for("delimitation-blind", summaries)
    assert set(metrics.defense_credited) == BLIND_CREDITED
    statuses = metrics.statuses
    assert {sid for sid, status in statuses.items() if status == "regression"} == BLIND_UNCREDITED
    for summary in summaries:
        # The stand-in follows the injection in the undefended leg every time.
        assert summary.baseline is not None and summary.baseline.security.verdict == "true"
    assert metrics.corpus["seeded_recall"] == 1.0
    assert metrics.labels_authored_against == "scripted"
    assert verify_bundle(root)["complete"]


def _imported_variant(scenario: Phase1Scenario) -> Phase1Scenario:
    data: dict[str, Any] = scenario.model_dump(mode="python", exclude_none=True)
    data.update(
        origin="imported",
        public_exposure=True,
        license="MIT",
        import_source={
            "framework": "agentdojo",
            "upstream_version": "unit-test-data-not-a-release",
            "license": "MIT",
            "case_id": "unit/case",
        },
    )
    return Phase1Scenario.model_validate(data)


def test_imported_and_exposed_cases_are_counted_and_labelled_from_the_scenarios(
    runs: dict[str, tuple[Path, list[RunSummary]]],
) -> None:
    """The counts cannot be faked: they are derived from each scenario's own 1.4 fields."""
    scenarios = committed_subset()
    variant = [_imported_variant(scenarios[0]), *scenarios[1:]]
    _, report, truth = build_subset()
    metrics = benchmark_metrics(
        subset="unit",
        stand_in="scripted",
        report=report,
        truth=truth,
        scenarios=variant,
        summaries=runs["scripted"][1],
    )
    assert metrics.origin_counts == {"authored": 5, "imported": 1}
    assert metrics.possibly_contaminated == (scenarios[0].scenario_id,)


def test_metrics_refuse_an_authored_corpus_scenario_or_a_foreign_run(
    runs: dict[str, tuple[Path, list[RunSummary]]],
) -> None:
    _, report, truth = build_subset()
    authored = load_scenario(ROOT / "scenarios" / "agent" / "agent-indirect-ticket.yaml")
    with pytest.raises(ValueError, match="must state its origin"):
        benchmark_metrics(
            subset="unit",
            stand_in="scripted",
            report=report,
            truth=truth,
            scenarios=[*committed_subset(), authored],
            summaries=runs["scripted"][1],
        )
    with pytest.raises(ValueError, match="outside the subset"):
        benchmark_metrics(
            subset="unit",
            stand_in="scripted",
            report=report,
            truth=truth,
            scenarios=committed_subset()[:1],
            summaries=runs["scripted"][1],
        )
    with pytest.raises(ValidationError):
        BenchmarkMetrics.model_validate(
            {**metrics_for("scripted", runs["scripted"][1]).model_dump(), "promoted": -1}
        )


# --- CLI ----------------------------------------------------------------------------------------


def test_cli_checks_promotion_and_runs_the_subset(tmp_path: Path) -> None:
    cli = CliRunner()
    promoted = cli.invoke(app, ["benchmark-promote"])
    assert promoted.exit_code == 0, promoted.output
    assert "attempted=8 promoted=6 not_promoted=2" in promoted.output
    ran = cli.invoke(
        app, ["benchmark-run", "--output-dir", str(tmp_path), "--stand-in", "scripted"]
    )
    assert ran.exit_code == 0, ran.output
    assert "authored=6 imported=0 possibly_contaminated=0" in ran.output
    written = json.loads((tmp_path / "metrics-scripted.json").read_text())
    assert written["promoted"] == 6 and written["attempted"] == 8
    unknown = cli.invoke(app, ["benchmark-run", "--output-dir", str(tmp_path), "--stand-in", "x"])
    assert unknown.exit_code == 1
    # A second run never writes over a sealed bundle.
    again = cli.invoke(
        app, ["benchmark-run", "--output-dir", str(tmp_path), "--stand-in", "scripted"]
    )
    assert again.exit_code == 1 and "not empty" in again.output
    assert verify_bundle(tmp_path / "scripted")["complete"]


def test_cli_reports_a_failed_run_without_a_traceback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import purpleloop.benchmark_cli as benchmark_cli

    async def broken(*args: object, **kwargs: object) -> list[RunSummary]:
        raise RuntimeError("fixture refused")

    monkeypatch.setattr(benchmark_cli, "run_subset", broken)
    result = CliRunner().invoke(app, ["benchmark-run", "--output-dir", str(tmp_path)])
    assert result.exit_code == 1 and "fixture refused" in result.output


def test_cli_refuses_to_run_a_drifted_subset(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import purpleloop.benchmark_cli as benchmark_cli

    monkeypatch.setattr(benchmark_cli, "subset_drift", lambda: ["ads-x.yaml"])
    cli = CliRunner()
    assert cli.invoke(app, ["benchmark-promote"]).exit_code == 1
    assert cli.invoke(app, ["benchmark-run", "--output-dir", str(tmp_path)]).exit_code == 1


def test_cli_write_rematerializes_the_subset_identically(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import purpleloop.benchmark_cli as benchmark_cli
    import purpleloop.runtime.benchmark as benchmark

    copy = tmp_path / "subset"
    shutil.copytree(SUBSET_DIR, copy)
    (copy / "ads-stray.yaml").write_text("schema_version: 1.4.0\n")
    monkeypatch.setattr(benchmark_cli, "write_subset", lambda: benchmark.write_subset(copy))
    result = CliRunner().invoke(app, ["benchmark-promote", "--write"])
    assert result.exit_code == 0, result.output
    assert not (copy / "ads-stray.yaml").exists()
    assert subset_drift(copy) == []
