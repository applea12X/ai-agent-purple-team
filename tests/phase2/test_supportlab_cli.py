from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from purpleloop.cli import app
from purpleloop.reporting.bundle import verify_bundle
from purpleloop.runtime.demo import ROOT


def test_estimate_run_and_bundle(tmp_path: Path) -> None:
    cli = CliRunner()
    scenario = ROOT / "scenarios/supportlab/bola-ticket.yaml"
    estimate = cli.invoke(app, ["supportlab-estimate", str(scenario)])
    assert estimate.exit_code == 0 and "requests" in estimate.output
    out = tmp_path / "run"
    result = cli.invoke(app, ["supportlab-run", str(scenario), str(out), "--fixture", "in-process"])
    assert result.exit_code == 0, result.output
    assert verify_bundle(out)["events"] > 0
    # Evidence is never overwritten.
    assert (
        cli.invoke(
            app, ["supportlab-run", str(scenario), str(out), "--fixture", "in-process"]
        ).exit_code
        == 1
    )
    assert cli.invoke(app, ["supportlab-estimate", str(tmp_path / "absent.yaml")]).exit_code == 1
