"""The Phase 5 CLI skeleton, its CI lane, and the earlier lanes it must leave untouched."""

from __future__ import annotations

import hashlib
import json

from typer.testing import CliRunner

from purpleloop.cli import app
from purpleloop.runtime.demo import ROOT
from purpleloop.schemas.phase5 import CONTRACT_VERSIONS

WORKFLOWS = ROOT / ".github" / "workflows"

#: SHA-256 of each earlier lane's workflow at the phase base (a79f185). Standing rule: Phase 5
#: never edits these; a new lane goes in phase5.yml.
EARLIER_WORKFLOWS = {
    "phase0.yml": "f5500a2c24e4dfabd0cb4336bd1543647bced7a87497a3434a9980d921764743",
    "phase1.yml": "9c19d790a61de6384349f4032fb47a58e8c9ade48740a0229d3c2bb977fc4503",
    "phase2.yml": "c701d3292e68b9a4ab33178b1ba94ab2bcf904bde0c79cd4caed404d0e767aef",
    "phase3.yml": "e891e174af28f9547226be9d703ad170825e541bfb6a61f75bbfe953ad36a7ee",
    "phase4.yml": "9ea11d8a91b47df72e7076561aee2b9f024c89b38c82a556d3d7925365998f5e",
}


def test_phase5_contracts_command_lists_every_contract_version() -> None:
    result = CliRunner().invoke(app, ["phase5-contracts"])
    assert result.exit_code == 0, result.output
    assert result.output.splitlines() == [
        f"{name} {version}" for name, version in CONTRACT_VERSIONS
    ]
    as_json = CliRunner().invoke(app, ["phase5-contracts", "--json"])
    assert as_json.exit_code == 0
    assert json.loads(as_json.output) == dict(CONTRACT_VERSIONS)


def test_earlier_lane_workflows_are_untouched() -> None:
    for name, digest in EARLIER_WORKFLOWS.items():
        assert hashlib.sha256((WORKFLOWS / name).read_bytes()).hexdigest() == digest, name


def test_phase5_lane_runs_the_phase5_suite() -> None:
    workflow = (WORKFLOWS / "phase5.yml").read_text()
    assert "uv run pytest tests/phase5" in workflow
    assert "uv run mypy" in workflow and "uv run ruff check ." in workflow
