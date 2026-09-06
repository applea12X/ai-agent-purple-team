from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from purpleloop.cli import app
from purpleloop.reporting.bundle import inventory, reports, verify_bundle
from purpleloop.runtime.demo import ROOT
from purpleloop.schemas.phase1 import load_scenario


def test_complete_offline_cli_and_bundle_tampering(tmp_path: Path) -> None:
    cli = CliRunner()
    result = cli.invoke(
        app, ["phase1-demo", "--fixture", "in-process", "--output-dir", str(tmp_path / "demo")]
    )
    assert result.exit_code == 0, result.output
    root = next((tmp_path / "demo").iterdir())
    assert verify_bundle(root)["scenarios"] == 5
    assert cli.invoke(app, ["verify-bundle", str(root)]).exit_code == 0
    assert (
        cli.invoke(app, ["validate-scenario", str(ROOT / "scenarios/phase1/bola.yaml")]).exit_code
        == 0
    )
    assert cli.invoke(app, ["validate-scenario", str(tmp_path / "absent")]).exit_code == 1
    assert cli.invoke(app, ["verify-bundle", str(tmp_path / "absent")]).exit_code == 1
    source = root / "bola"
    cases = [
        "digest",
        "missing",
        "reference",
        "unsafe",
        "incomplete",
        "no-inspect",
        "incident",
        "extra",
    ]
    for case in cases:
        destination = tmp_path / case
        shutil.copytree(source, destination)
        if case == "digest":
            (destination / "report.html").write_text("tampered")
        elif case == "missing":
            (destination / "plan.json").unlink()
            inventory(destination, complete=True)
        elif case == "reference":
            summary = json.loads((destination / "summary.json").read_text())
            summary["findings"][0]["evidence_ids"] = ["nonexistent"]
            (destination / "summary.json").write_text(json.dumps(summary))
            inventory(destination, complete=True)
        elif case == "unsafe":
            raw = json.loads((destination / "inventory.json").read_text())
            raw["artifacts"]["../escape"] = "0" * 64
            (destination / "inventory.json").write_text(json.dumps(raw))
        elif case == "incomplete":
            inventory(destination, complete=False)
        elif case == "no-inspect":
            shutil.rmtree(destination / "inspect")
            inventory(destination, complete=True)
        elif case == "incident":
            summary = json.loads((destination / "summary.json").read_text())
            summary["evidence_integrity_incident"] = True
            (destination / "summary.json").write_text(json.dumps(summary))
            inventory(destination, complete=True)
        elif case == "extra":
            (destination / "unexpected.txt").write_text("untracked")
        with pytest.raises((ValueError, OSError)):
            verify_bundle(destination)


async def test_report_outcome_semantics(
    make_runner: Any, scenarios: Any, phase1_manifest: Any, tmp_path: Path
) -> None:
    import xml.etree.ElementTree as ET

    runner, _, directory = make_runner()
    summary = await runner.run(scenarios[0], phase1_manifest, run_id="report", output_dir=directory)
    summaries = [
        summary.model_copy(update={"status": status, "reason": "synthetic report test"})
        for status in ("passed", "regression", "error", "inconclusive")
    ]
    reports(tmp_path, summaries)
    suite = ET.parse(tmp_path / "report.xml").getroot()  # noqa: S314 -- generated test output
    assert suite.attrib["tests"] == "4"
    assert (
        len(suite.findall(".//failure"))
        == len(suite.findall(".//error"))
        == len(suite.findall(".//skipped"))
        == 1
    )


def test_legacy_conversion_is_lossless_and_not_silently_runnable(
    tmp_path: Path, action: Any, manifest: Any
) -> None:
    legacy = dict(
        schema_version="1.0.0",
        scenario_id="legacy",
        scenario_version="1.0.0",
        authorization_digest=manifest.manifest_digest(),
        target_mode="mock",
        fixture_seed=1,
        actor_id="customer-a",
        actor_role="customer",
        tenant_id="tenant-a",
        taxonomy_mappings={},
        legitimate_objective="read",
        attacker_objective="read",
        actions=[action.model_dump(mode="json")],
        expected_evidence=["result"],
        deterministic_oracle="state",
        utility_oracle="utility",
        defense_profile="defense",
        reset_fixture="reset",
        provenance="original",
        license="CC0-1.0",
    )
    path = tmp_path / "legacy.json"
    path.write_text(json.dumps(legacy))
    converted = load_scenario(path)
    assert converted.legacy_actions[0].digest() == action.digest()
    assert converted.clean_steps == converted.attack_steps == ()
    assert converted.provenance == "original"
    with pytest.raises(ValueError, match="clean"):
        converted.require_runnable()
    path.write_text("[]")
    with pytest.raises(ValueError):
        load_scenario(path)
