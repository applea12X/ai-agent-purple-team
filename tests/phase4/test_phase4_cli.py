"""WP4 CLI surface: gates over a real bundle, injections, attestation, audit, and smoke.

The injection cases here are the local half of the red-branch protocol: each gate class is
fed a deliberately violating input through the *same* command CI runs, and the command exits
nonzero with the gate named. The CI half (a red branch per class, observed red at its own
gate) is recorded in the acceptance record when the branches are pushed.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from purpleloop.agent_cli import run_offline_scenario
from purpleloop.cli import app
from purpleloop.reporting.bundle import verify_bundle
from purpleloop.runtime.demo import ROOT
from purpleloop.schemas.phase4 import RiskClassBaseline

runner = CliRunner()

JUNIT_PASSING = """<?xml version="1.0" encoding="utf-8"?>
<testsuites><testsuite name="pytest">
  <testcase classname="tests.phase1.test_loop" name="test_all_five_paired_loops"/>
  <testcase classname="tests.phase2.test_supportlab_loop" name="test_full_corpus_paired_loops"/>
  <testcase classname="tests.phase3.test_agent_corpus"
            name="test_corpus_metrics_over_the_whole_agent_corpus"/>
</testsuite></testsuites>
"""


@pytest.fixture(scope="module")
def bundle(tmp_path_factory: pytest.TempPathFactory) -> Path:
    directory = tmp_path_factory.mktemp("cli") / "agent-goal-hijack"
    summary = asyncio.run(
        run_offline_scenario(ROOT / "scenarios" / "agent" / "agent-goal-hijack.yaml", directory)
    )
    assert summary.status == "passed"
    verify_bundle(directory)
    return directory


@pytest.fixture(scope="module")
def gate_inputs(tmp_path_factory: pytest.TempPathFactory) -> dict[str, Path]:
    scratch = tmp_path_factory.mktemp("gate-inputs")
    junit = scratch / "junit.xml"
    junit.write_text(JUNIT_PASSING)
    # The committed corpus baseline doubles as the current-metrics document for a clean pass:
    # identical metrics are, by definition, within baseline.
    return {"junit": junit, "current": ROOT / "baselines" / "corpus-baseline.json"}


def gates_argv(bundle: Path, inputs: dict[str, Path], *extra: str) -> list[str]:
    return [
        "gates",
        str(bundle),
        "--junit",
        str(inputs["junit"]),
        "--risk-current",
        str(inputs["current"]),
        *extra,
    ]


def test_gates_pass_over_a_clean_bundle(bundle: Path, gate_inputs: dict[str, Path]) -> None:
    result = runner.invoke(app, gates_argv(bundle, gate_inputs))
    assert result.exit_code == 0, result.output
    assert result.output.count("pass") >= 5 and "BLOCKED" not in result.output


@pytest.mark.parametrize(
    ("gate", "reason"),
    [
        ("scope-bypass", "SCOPE_BYPASS"),
        ("critical-regression", "REGISTRY_TEST_FAILED"),
        ("schema-drift", "SCHEMA_DIGEST_DRIFT"),
        ("budget-failure", "BUDGET_VIOLATION"),
        ("risk-class-regression", "RISK_CLASS_REGRESSION"),
    ],
)
def test_each_injected_violation_blocks_its_own_gate(
    bundle: Path, gate_inputs: dict[str, Path], gate: str, reason: str
) -> None:
    result = runner.invoke(app, gates_argv(bundle, gate_inputs, "--inject", gate))
    assert result.exit_code == 1, result.output
    assert f"INJECTED {gate}" in result.output
    assert reason in result.output
    # Exactly one gate blocks: the failure is attributable to the injected class.
    assert result.output.count("BLOCKED") == 1


def test_gates_write_their_decisions_when_asked(
    bundle: Path, gate_inputs: dict[str, Path], tmp_path: Path
) -> None:
    out = tmp_path / "gates.json"
    result = runner.invoke(app, gates_argv(bundle, gate_inputs, "--output", str(out)))
    assert result.exit_code == 0, result.output
    decisions = json.loads(out.read_text())["decisions"]
    assert len(decisions) == 5 and not any(item["blocked"] for item in decisions)


def test_gates_refuse_an_unknown_injection(bundle: Path, gate_inputs: dict[str, Path]) -> None:
    result = runner.invoke(app, gates_argv(bundle, gate_inputs, "--inject", "vibes"))
    assert result.exit_code == 1 and "not an injectable gate class" in result.output


def test_attest_verify_and_audit_export_chain(bundle: Path, tmp_path: Path) -> None:
    attested = runner.invoke(app, ["attest-bundle", str(bundle)])
    assert attested.exit_code == 0 and "ATTESTED run-bundle" in attested.output
    verified = runner.invoke(app, ["verify-bundle", str(bundle), "--attestation"])
    assert verified.exit_code == 0 and "attestation" in verified.output
    solo = runner.invoke(app, ["verify-attestation", str(bundle)])
    assert solo.exit_code == 0 and "ephemeral" in solo.output
    out = tmp_path / "audit.json"
    exported = runner.invoke(app, ["audit-export", str(bundle), str(out)])
    assert exported.exit_code == 0, exported.output
    export = json.loads(out.read_text())
    assert export["runs"][0]["status"] == "passed"
    assert export["runs"][0]["decisions"], "the decision record must not be empty"
    assert export["attestation"] is not None
    assert "how_to_verify" in export


def test_audit_export_is_redacted(bundle: Path, tmp_path: Path) -> None:
    """The export embeds only already-redacted artifacts; no live credential appears."""
    out = tmp_path / "audit.json"
    assert runner.invoke(app, ["audit-export", str(bundle), str(out)]).exit_code == 0
    manifest = json.loads((bundle / "manifest.json").read_text())
    text = out.read_text()
    for handle in manifest.get("credential_handles", []):
        assert handle in text  # handles are data, not secrets, and should survive
    assert "SYNTHETIC-CREDENTIAL" not in text
    assert "[REDACTED]" not in json.dumps(json.loads(text)["runs"][0]["decisions"])


def test_holdout_check_denies_every_mutation() -> None:
    result = runner.invoke(app, ["holdout-check"])
    assert result.exit_code == 0, result.output
    assert "17/17 mutations denied" in result.output
    assert "PERMITTED" not in result.output


def test_schema_baseline_writes_the_reference_digests(tmp_path: Path) -> None:
    out = tmp_path / "digests.json"
    result = runner.invoke(app, ["schema-baseline", "--output", str(out)])
    assert result.exit_code == 0
    digests = json.loads(out.read_text())["digests"]
    assert "authorization-manifest-1.4" in digests and "run-attestation-1.0" in digests


def test_smoke_demo_runs_all_three_lanes(tmp_path: Path) -> None:
    result = runner.invoke(app, ["smoke-demo", "--output-dir", str(tmp_path / "smoke")])
    assert result.exit_code == 0, result.output
    for line in ("phase1/bola", "supportlab/bola-ticket-ui", "agent/agent-direct-injection"):
        assert line in result.output
    assert "wall time" in result.output
    root = next((tmp_path / "smoke").iterdir())
    suite = json.loads((root / "suite.json").read_text())
    assert suite["lane"] == "smoke" and len(suite["scenarios"]) == 14
    assert suite["wall_time_seconds"] > 0
    assert verify_bundle(root)["valid"] is True


def test_corpus_baseline_document_is_committed_and_valid() -> None:
    baseline = RiskClassBaseline.model_validate_json(
        (ROOT / "baselines" / "corpus-baseline.json").read_text()
    )
    assert baseline.corpus == "scenarios/agent"
    assert sum(entry.scenarios for entry in baseline.classes) == 25
    assert all(entry.seeded_false_negatives == 0 for entry in baseline.classes)
