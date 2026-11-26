"""The incident drill's tools (loose end 4.12): what the runbook needed and lacked.

Each test runs against the committed sample bundles, copied: the ledgers, plans, and the
deliberately corrupted incident sample are real artifacts, so the lookups are exercised on the
same inputs an operator following ``docs/incident-runbook.md`` would have.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

from typer.testing import CliRunner

from purpleloop.cli import app
from purpleloop.reporting.gates import scope_gate
from purpleloop.reporting.incident_tools import first_ledger_break, locate_action
from purpleloop.runtime.demo import ROOT
from purpleloop.runtime.ledger import EvidenceLedger
from purpleloop.schemas.action import ActionRequest

SAMPLES = ROOT / "docs" / "samples"
DRILL = ROOT / "scripts" / "incident_drill.py"


def test_the_first_broken_event_of_the_incident_sample_is_named() -> None:
    # The sample's README: one byte of event 3 (line 4) was altered after sealing.
    assert first_ledger_break(SAMPLES / "incident" / "evidence.jsonl")["line"] == 4
    assert first_ledger_break(SAMPLES / "passing-run" / "evidence.jsonl") == {
        "valid": True,
        "events": 102,
    }


def test_a_rewritten_but_well_formed_event_is_caught_by_its_hash(tmp_path: Path) -> None:
    ledger = tmp_path / "evidence.jsonl"
    lines = (SAMPLES / "passing-run" / "evidence.jsonl").read_text().splitlines()
    event = json.loads(lines[5])
    event["reason_code"] = "EDITED"
    lines[5] = json.dumps(event)
    ledger.write_text("\n".join(lines) + "\n")
    result = first_ledger_break(ledger)
    assert (result["line"], result["sequence"]) == (6, 5)
    assert "own hash" in result["reason"]
    original = (SAMPLES / "passing-run" / "evidence.jsonl").read_text()
    ledger.write_text(original)
    (tmp_path / "evidence.jsonl.anchor").write_text("0" * 64)
    assert "anchor" in first_ledger_break(ledger)["reason"]
    command = CliRunner().invoke(app, ["locate-ledger-break", str(ledger)])
    assert command.exit_code == 1


def test_a_digest_is_traced_to_its_plan_node_its_compiled_intent_or_neither() -> None:
    run = SAMPLES / "passing-run"
    plan = json.loads((run / "plan.json").read_text())
    node = plan["nodes"][0]
    digest = ActionRequest.model_validate(node["action"]).digest()
    found = locate_action(run, digest)
    assert found["origins"] == [f"plan node {node['node_id']} (stage {node['stage']})"]
    assert any(item["kind"] == "policy" for item in found["events"])
    compiled = next(
        json.loads(line)
        for line in (run / "evidence.jsonl").read_text().splitlines()
        if '"TOOL_INTENT_COMPILED"' in line
    )
    intent = ActionRequest.model_validate(compiled["data"]["action"]).digest()
    assert any("model intent compiled" in o for o in locate_action(run, intent)["origins"])
    nowhere = locate_action(run, "f" * 64)
    assert nowhere["events"] == [] and "neither" in nowhere["origins"][0]


def _suite(tmp_path: Path) -> Path:
    suite = tmp_path / "suite"
    shutil.copytree(SAMPLES / "passing-run", suite / "a-run")
    shutil.copytree(SAMPLES / "denied-run", suite / "b-run")
    return suite


def _events(suite: Path) -> list:  # type: ignore[type-arg]
    return [e for p in sorted(suite.rglob("evidence.jsonl")) for e in EvidenceLedger(p).verify()]


def test_the_drill_script_materializes_a_bypass_the_scope_gate_blocks(tmp_path: Path) -> None:
    for mode in ("scope-bypass", "cross-run-bypass"):
        suite = _suite(tmp_path / mode)
        assert not scope_gate(_events(suite)).blocked
        done = subprocess.run(  # noqa: S603 -- fixed argv
            [sys.executable, str(DRILL), mode, str(suite)], capture_output=True, text=True
        )
        assert done.returncode == 0, done.stderr
        decision = scope_gate(_events(suite))  # the ledgers still verify: an honest record
        assert decision.blocked and decision.reason_code == "SCOPE_BYPASS", mode
        assert (suite / ".incident-drill").is_file()


def test_the_drill_script_refuses_the_repository() -> None:
    done = subprocess.run(  # noqa: S603 -- fixed argv
        [sys.executable, str(DRILL), "scope-bypass", str(SAMPLES / "passing-run")],
        capture_output=True,
        text=True,
    )
    assert done.returncode == 2 and "refusing" in done.stdout
