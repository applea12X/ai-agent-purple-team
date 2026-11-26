"""WP5.3.6: ``purpleloop analyze`` -- verified bundles to Parquet, queried with DuckDB.

The export reads verified bundles only (plan §5 "Contract"), refuses an unverified, tampered,
or incomplete one before writing anything, refuses a tampered Parquet file before querying, and
runs analyst SQL with no file access. The numbers it returns are checked against the ledgers
and summaries they came from, so a faked row count fails.
"""

from __future__ import annotations

import asyncio
import json
import shutil
from collections import Counter
from pathlib import Path

import duckdb
import pytest
from typer.testing import CliRunner

from purpleloop.cli import app
from purpleloop.reporting.analysis import TABLES, AnalysisRefused, analyze, query
from purpleloop.reporting.telemetry import FileExporter
from purpleloop.runtime.ledger import EvidenceLedger
from purpleloop.schemas.phase1 import RunSummary
from purpleloop.telemetry_cli import ObservedLane, observe_suite

CASES = ("agent-canary-exfiltration", "agent-indirect-ticket")


@pytest.fixture(scope="module")
def suite(tmp_path_factory: pytest.TempPathFactory) -> Path:
    root = tmp_path_factory.mktemp("analysis") / "bundle"
    export = tmp_path_factory.mktemp("analysis-export") / "spans.jsonl"
    asyncio.run(observe_suite(ObservedLane.AGENT, root, FileExporter(export), scenario_ids=CASES))
    return root


def test_analyze_writes_every_table_and_the_numbers_match_the_bundle(
    suite: Path, tmp_path: Path
) -> None:
    out = tmp_path / "analysis"
    export = analyze([suite], out)
    assert export.bundles == 1 and export.runs == len(CASES)
    manifest = json.loads((out / "analysis.json").read_text())
    assert set(manifest["tables"]) == set(TABLES)
    for name in TABLES:
        assert (out / f"{name}.parquet").is_file()
    ledgers = {case: EvidenceLedger(suite / case / "evidence.jsonl").verify() for case in CASES}
    summaries = {
        case: RunSummary.model_validate_json((suite / case / "summary.json").read_text())
        for case in CASES
    }
    assert export.rows["events"] == sum(len(events) for events in ledgers.values())
    _, rows = query(out, "SELECT run_id, status, event_replay_hash FROM runs ORDER BY run_id")
    assert rows == sorted(
        (case, summaries[case].status, summaries[case].event_replay_hash) for case in CASES
    )
    _, kinds = query(out, "SELECT kind, count(*) FROM events GROUP BY kind")
    expected = Counter(str(e.kind) for events in ledgers.values() for e in events)
    assert dict(kinds) == dict(expected)
    _, findings = query(out, "SELECT count(*) FROM findings")
    assert findings[0][0] == sum(len(s.findings) for s in summaries.values())
    _, detections = query(out, "SELECT count(*) FROM detections WHERE observed")
    assert detections[0][0] == sum(
        d.observed
        for s in summaries.values()
        for leg in (s.baseline, s.replay)
        if leg is not None
        for d in leg.detectors
    )


def test_a_tampered_bundle_is_refused_before_anything_is_written(
    suite: Path, tmp_path: Path
) -> None:
    tampered = tmp_path / "tampered"
    shutil.copytree(suite, tampered)
    ledger = tampered / CASES[0] / "evidence.jsonl"
    ledger.write_text(ledger.read_text().replace("COMPLETED", "C0MPLETED", 1))
    out = tmp_path / "out"
    with pytest.raises(AnalysisRefused) as refused:
        analyze([suite, tampered], out)
    assert refused.value.reason_code == "BUNDLE_NOT_VERIFIED"
    assert not out.exists()


def test_an_incomplete_bundle_is_refused_unless_partial_is_explicit(
    suite: Path, tmp_path: Path
) -> None:
    partial = tmp_path / "partial"
    shutil.copytree(suite / CASES[0], partial)
    inventory = json.loads((partial / "inventory.json").read_text())
    inventory["complete"] = False
    (partial / "inventory.json").write_text(json.dumps(inventory))
    with pytest.raises(AnalysisRefused):
        analyze([partial], tmp_path / "a")
    assert analyze([partial], tmp_path / "b", allow_partial=True).runs == 1


def test_missing_bundles_and_non_empty_outputs_are_refused(suite: Path, tmp_path: Path) -> None:
    with pytest.raises(AnalysisRefused, match="NO_BUNDLES"):
        analyze([], tmp_path / "x")
    with pytest.raises(AnalysisRefused, match="BUNDLE_NOT_VERIFIED"):
        analyze([tmp_path / "nowhere"], tmp_path / "y")
    occupied = tmp_path / "occupied"
    occupied.mkdir()
    (occupied / "keep.txt").write_text("x")
    with pytest.raises(AnalysisRefused, match="OUTPUT_NOT_EMPTY"):
        analyze([suite], occupied)


def test_a_tampered_parquet_file_is_refused(suite: Path, tmp_path: Path) -> None:
    out = tmp_path / "analysis"
    analyze([suite], out)
    target = out / "runs.parquet"
    target.write_bytes(target.read_bytes() + b"\0")
    with pytest.raises(AnalysisRefused, match="EXPORT_NOT_VERIFIED"):
        query(out, "SELECT 1")
    with pytest.raises(AnalysisRefused, match="EXPORT_NOT_VERIFIED"):
        query(tmp_path / "missing", "SELECT 1")
    manifest = json.loads((out / "analysis.json").read_text())
    manifest["tables"]["evil; DROP"] = manifest["tables"].pop("runs")
    (out / "analysis.json").write_text(json.dumps(manifest))
    with pytest.raises(AnalysisRefused, match="does not match"):
        query(out, "SELECT 1")


def test_analyst_sql_has_no_file_access(suite: Path, tmp_path: Path) -> None:
    out = tmp_path / "analysis"
    analyze([suite], out)
    secret = tmp_path / "outside.csv"
    secret.write_text("a\n1\n")
    with pytest.raises(duckdb.Error):
        query(out, f"SELECT * FROM read_csv('{secret}')")  # noqa: S608 - the attempt is the test
    with pytest.raises(duckdb.Error):
        query(out, f"COPY runs TO '{tmp_path / 'leak.csv'}'")
    assert not (tmp_path / "leak.csv").exists()
    with pytest.raises(duckdb.Error):
        query(out, "SET enable_external_access = true")


def test_analyze_cli(suite: Path, tmp_path: Path) -> None:
    runner = CliRunner()
    out = tmp_path / "cli"
    result = runner.invoke(
        app, ["analyze", str(suite), "--out", str(out), "--query", "SELECT count(*) FROM runs"]
    )
    assert result.exit_code == 0, result.output
    assert result.output.strip().splitlines()[-1] == str(len(CASES))
    again = runner.invoke(app, ["analyze-query", str(out), "SELECT status FROM runs LIMIT 1"])
    assert again.exit_code == 0 and "passed" in again.output
    refused = runner.invoke(app, ["analyze", str(tmp_path / "nope"), "--out", str(tmp_path / "z")])
    assert refused.exit_code == 1 and "REFUSED" in refused.output
    bad = runner.invoke(app, ["analyze-query", str(tmp_path / "nope"), "SELECT 1"])
    assert bad.exit_code == 1


def test_telemetry_export_cli_matches_and_refuses(suite: Path, tmp_path: Path) -> None:
    runner = CliRunner()
    spans = tmp_path / "after" / "spans.jsonl"
    result = runner.invoke(app, ["telemetry-export", str(suite), "--spans", str(spans)])
    assert result.exit_code == 0, result.output
    assert json.loads(result.output)["runs"] == len(CASES)
    inside = runner.invoke(
        app, ["telemetry-export", str(suite), "--spans", str(suite / "spans.jsonl")]
    )
    assert inside.exit_code == 1
    unverified = runner.invoke(app, ["telemetry-export", str(tmp_path), "--spans", str(spans)])
    assert unverified.exit_code == 1


def test_observe_suite_cli_writes_a_verified_bundle_and_export(tmp_path: Path) -> None:
    result = CliRunner().invoke(
        app,
        [
            "observe-suite",
            "--lane",
            "supportlab",
            "--out",
            str(tmp_path / "suite"),
            "--spans",
            str(tmp_path / "export" / "spans.jsonl"),
            "--scenario",
            "bola-ticket",
        ],
    )
    assert result.exit_code == 0, result.output
    counts, latency = (json.loads(line) for line in result.output.strip().splitlines()[-2:])
    assert counts["runs"] == 1 and counts["export_failures"] == 0 and counts["spans_exported"]
    assert latency["wall_clock_ms"]["label"] == "wall clock on this machine"
