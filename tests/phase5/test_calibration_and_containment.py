"""WP5.0.3 and WP5.0.6 mechanisms: a pin calibrated from evidence, containment held from evidence.

No calibration number is invented here: every figure is computed from MODEL_CALLED records of a
run the test performs (offline, or through a stub endpoint) and compared with the records
themselves. The containment check is shown to hold over a captured model's bundles and to name a
violation when one is planted in the events, so a check that always passes would fail this file.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from statistics import mean
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from typer.testing import CliRunner

from purpleloop.adapters.agent import SYSTEM_PROMPT_HASH
from purpleloop.adapters.scripted_model import HostileModel
from purpleloop.agent_cli import _runner_factory, networked_provider
from purpleloop.cli import app
from purpleloop.control.model_config import (
    CalibrationMismatch,
    apply_calibration,
    calibration_filename,
    load_calibration,
)
from purpleloop.runtime.demo import ROOT
from purpleloop.schemas.authorization import AuthorizationManifest
from purpleloop.schemas.model_calibration import PinCalibration
from purpleloop.schemas.phase1 import Phase1Scenario, load_scenario
from purpleloop.schemas.phase3 import DecodingParameters
from purpleloop.scoring.calibration import (
    CalibrationError,
    MeasuredCalls,
    bundle_directories,
    check_against,
    compute_calibration,
    read_calls,
)
from purpleloop.scoring.containment import check_events, check_tree

runner = CliRunner()
SCENARIO = ROOT / "scenarios" / "agent" / "agent-indirect-ticket.yaml"
OLLAMA = ["--endpoint", "http://127.0.0.1:11434/v1", "--profile", "ollama"]
IDENTITY = ["--model-id", "qwen2.5:7b-instruct", "--model-version", "845dbda0ea48"]
Events = Callable[[Path], list[dict[str, Any]]]


def calls_in(root: Path, read_events: Events) -> list[dict[str, Any]]:
    return [
        event["data"]["call"]
        for directory in bundle_directories(root)
        for event in read_events(directory)
        if event["kind"] == "model" and event["reason_code"] == "MODEL_CALLED"
    ]


@pytest.fixture
def stub_run(tmp_path: Path, stub_model: Any) -> Path:
    """Three repetitions through a stub whose token counts vary per call."""
    counts = iter(range(1000))

    def vary(body: dict[str, Any]) -> str:
        index = next(counts)
        stub_model.prompt_tokens = 400 + 7 * (index % 5)
        stub_model.completion_tokens = 20 + 3 * (index % 4)
        return '{"message": "Answered.", "tool_intents": []}'

    stub_model.content = vary
    out = tmp_path / "measured"
    result = runner.invoke(
        app, ["agent-run", str(SCENARIO), str(out), *OLLAMA, *IDENTITY, "--repetitions", "3"]
    )
    assert "FAILED" not in result.output, result.output
    return out


# --- calibrate-pin --------------------------------------------------------------------------------


def test_calibrate_pin_writes_the_mean_of_the_recorded_calls(
    tmp_path: Path, stub_run: Path, read_events: Events, monkeypatch: pytest.MonkeyPatch
) -> None:
    calibration_dir = tmp_path / "baselines"
    monkeypatch.setenv("PURPLELOOP_MODEL_CALIBRATION_DIR", str(calibration_dir))
    result = runner.invoke(app, ["calibrate-pin", str(stub_run)])
    assert result.exit_code == 0, result.output
    path = calibration_dir / "ollama-qwen2.5_7b-instruct-845dbda0ea48.json"
    calibration = load_calibration(path)
    calls = calls_in(stub_run, read_events)
    inputs = [call["input_tokens"] for call in calls]
    outputs = [call["output_tokens"] for call in calls]
    assert calibration.calls == len(calls) and calibration.bundles == 3
    assert calibration.expected_input_tokens_per_call == int(mean(inputs) + 0.5)
    assert calibration.expected_output_tokens_per_call == int(mean(outputs) + 0.5)
    assert (calibration.input_tokens_min, calibration.input_tokens_max) == (
        min(inputs),
        max(inputs),
    )
    assert (calibration.output_tokens_min, calibration.output_tokens_max) == (
        min(outputs),
        max(outputs),
    )
    assert calibration.system_prompt_hash == SYSTEM_PROMPT_HASH
    assert calibration.decodings == (DecodingParameters(seed=42),)
    assert len(calibration.evidence_digests) == 3
    assert f"n={len(calls)}" in result.output


def test_a_committed_calibration_is_loaded_into_the_signed_pin(
    tmp_path: Path, stub_run: Path, stub_model: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    calibration_dir = tmp_path / "baselines"
    monkeypatch.setenv("PURPLELOOP_MODEL_CALIBRATION_DIR", str(calibration_dir))
    assert runner.invoke(app, ["calibrate-pin", str(stub_run)]).exit_code == 0
    held = load_calibration(next(calibration_dir.glob("*.json")))
    monkeypatch.setenv("PURPLELOOP_MODEL_ID", "qwen2.5:7b-instruct")
    monkeypatch.setenv("PURPLELOOP_MODEL_VERSION", "845dbda0ea48")
    _, pin = networked_provider("http://127.0.0.1:11434/v1", "ollama")
    assert pin.expected_input_tokens_per_call == held.expected_input_tokens_per_call
    assert pin.expected_output_tokens_per_call == held.expected_output_tokens_per_call
    out = tmp_path / "calibrated"
    result = runner.invoke(app, ["agent-run", str(SCENARIO), str(out), *OLLAMA])
    assert "FAILED" not in result.output, result.output
    (signed,) = json.loads((out / SCENARIO.stem / "manifest.json").read_text())["phase3"][
        "model_pins"
    ]
    assert signed["expected_input_tokens_per_call"] == held.expected_input_tokens_per_call
    # Another version of the same model is a different pin and gets no calibration.
    monkeypatch.setenv("PURPLELOOP_MODEL_VERSION", "other")
    _, other = networked_provider("http://127.0.0.1:11434/v1", "ollama")
    assert other.expected_input_tokens_per_call == 0


def test_a_stale_calibration_is_refused_rather_than_applied(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, stub_model: Any
) -> None:
    """A calibration measured under another system prompt says nothing about this one."""
    calibration_dir = tmp_path / "baselines"
    calibration_dir.mkdir()
    stale = PinCalibration(
        provider="ollama",
        model_id="m",
        model_version="v",
        system_prompt_hash="0" * 64,
        expected_input_tokens_per_call=400,
        expected_output_tokens_per_call=30,
        calls=6,
        input_tokens_min=380,
        input_tokens_max=420,
        output_tokens_min=20,
        output_tokens_max=40,
        decodings=(DecodingParameters(seed=42),),
        bundles=1,
        evidence_digests=("a" * 64,),
    )
    (calibration_dir / calibration_filename("ollama", "m", "v")).write_text(stale.model_dump_json())
    monkeypatch.setenv("PURPLELOOP_MODEL_CALIBRATION_DIR", str(calibration_dir))
    result = runner.invoke(
        app,
        [
            "agent-run",
            str(SCENARIO),
            str(tmp_path / "o"),
            *OLLAMA,
            "--model-id",
            "m",
            "--model-version",
            "v",
        ],
    )
    assert result.exit_code == 1 and "system_prompt_hash differ" in result.output
    assert not stub_model.requests
    _, pin = networked_provider("http://127.0.0.1:11434/v1", "ollama")
    with pytest.raises(
        CalibrationMismatch, match="model_id, model_version, system_prompt_hash differ"
    ):
        apply_calibration(pin, stale)


def test_a_malformed_calibration_file_is_refused(tmp_path: Path) -> None:
    path = tmp_path / "bad.json"
    path.write_text('{"schema_version": "1.5.0"}')
    with pytest.raises(CalibrationMismatch, match="invalid"):
        load_calibration(path)


def test_calibration_refuses_mixed_pins_no_calls_and_no_usage(
    tmp_path: Path, stub_run: Path, stub_model: Any
) -> None:
    measured = read_calls(stub_run)
    with pytest.raises(CalibrationError, match="at least 1000"):
        compute_calibration(measured, min_calls=1000)
    other = measured.records[0].model_copy(update={"model_id": "another"})
    mixed = MeasuredCalls(
        records=(*measured.records, other),
        bundles=measured.bundles,
        evidence_digests=measured.evidence_digests,
        pins=measured.pins,
    )
    with pytest.raises(CalibrationError, match="2 pin identities"):
        compute_calibration(mixed)
    silent = MeasuredCalls(
        records=tuple(r.model_copy(update={"output_tokens": 0}) for r in measured.records),
        bundles=measured.bundles,
        evidence_digests=measured.evidence_digests,
        pins=measured.pins,
    )
    with pytest.raises(CalibrationError, match="no token usage"):
        compute_calibration(silent)
    assert not read_calls(stub_run, pin_id="nope").records
    with pytest.raises(CalibrationError, match="no run bundle"):
        read_calls(tmp_path / "empty-dir-that-does-not-exist")


def test_a_tampered_bundle_cannot_be_calibrated_from(tmp_path: Path, stub_run: Path) -> None:
    bundle = bundle_directories(stub_run)[0]
    evidence = bundle / "evidence.jsonl"
    assert '"input_tokens":4' in evidence.read_text()
    evidence.write_text(evidence.read_text().replace('"input_tokens":4', '"input_tokens":9', 1))
    result = runner.invoke(app, ["calibrate-pin", str(stub_run), "--output", str(tmp_path / "x")])
    assert result.exit_code == 1 and "does not verify" in result.output
    assert not (tmp_path / "x").exists()


def test_calibration_check_reports_the_delta_against_the_held_figures(
    tmp_path: Path, stub_run: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    held = compute_calibration(read_calls(stub_run))
    check = check_against(read_calls(stub_run), held)
    # Checked against the run it was computed from, the only gap is the rounding of the mean.
    assert check.calls == held.calls and not check.estimate_is_bound
    assert check.accounting.within_tolerance["tokens"]
    assert abs(check.accounting.delta_percent["tokens"]) < 1.0
    # A calibration that is 50% low is reported as a miss, not tuned to pass.
    low = held.model_copy(
        update={
            "expected_input_tokens_per_call": held.expected_input_tokens_per_call // 2,
            "expected_output_tokens_per_call": held.expected_output_tokens_per_call // 2,
        }
    )
    missed = check_against(read_calls(stub_run), low)
    assert not missed.accounting.within_tolerance["tokens"]
    assert missed.accounting.delta_percent["tokens"] > 90
    path = tmp_path / "held.json"
    path.write_text(held.model_dump_json())
    result = runner.invoke(
        app,
        [
            "calibration-check",
            str(stub_run),
            "--calibration",
            str(path),
            "--output",
            str(tmp_path / "c.json"),
        ],
    )
    assert result.exit_code == 0, result.output
    payload = json.loads((tmp_path / "c.json").read_text())
    assert payload["accounting"]["actual_tokens"] == check.accounting.actual_tokens
    assert "within=True" in result.output


def test_calibration_check_refuses_an_unrelated_calibration(tmp_path: Path, stub_run: Path) -> None:
    held = compute_calibration(read_calls(stub_run)).model_copy(update={"model_id": "other"})
    with pytest.raises(CalibrationError, match="no measured call matches"):
        check_against(read_calls(stub_run), held)
    path = tmp_path / "other.json"
    path.write_text(held.model_dump_json())
    result = runner.invoke(app, ["calibration-check", str(stub_run), "--calibration", str(path)])
    assert result.exit_code == 1


def test_a_priced_run_checks_cost_against_the_signed_price(tmp_path: Path, stub_model: Any) -> None:
    stub_model.prompt_tokens, stub_model.completion_tokens = 1000, 100
    out = tmp_path / "priced"
    result = runner.invoke(
        app,
        [
            "agent-run",
            str(SCENARIO),
            str(out),
            *OLLAMA,
            "--price-input-microusd-per-1k",
            "150",
            "--price-output-microusd-per-1k",
            "600",
        ],
    )
    assert "FAILED" not in result.output, result.output
    measured = read_calls(out)
    held = compute_calibration(measured)
    check = check_against(measured, held)
    per_call = -(-(1000 * 150 + 100 * 600) // 1000)
    assert check.accounting.actual_cost_microusd == per_call * check.calls
    assert check.accounting.estimated_cost_microusd == per_call * check.calls
    assert check.pin.price_input_microusd_per_1k == 150


def test_calibrate_pin_cli_reports_a_refusal(tmp_path: Path) -> None:
    result = runner.invoke(app, ["calibrate-pin", str(tmp_path)])
    assert result.exit_code == 1 and "no run bundle" in result.output


def test_the_calibration_document_rejects_inconsistent_figures() -> None:
    base = {
        "provider": "ollama",
        "model_id": "m",
        "system_prompt_hash": "0" * 64,
        "expected_input_tokens_per_call": 400,
        "expected_output_tokens_per_call": 30,
        "calls": 2,
        "input_tokens_min": 380,
        "input_tokens_max": 420,
        "output_tokens_min": 20,
        "output_tokens_max": 40,
        "decodings": [{"seed": 42}],
        "bundles": 1,
        "evidence_digests": ["a" * 64],
    }
    PinCalibration.model_validate(base)
    for change in (
        {"expected_input_tokens_per_call": 500},
        {"expected_output_tokens_per_call": 10},
        {"bundles": 2},
    ):
        with pytest.raises(ValueError):
            PinCalibration.model_validate({**base, **change})


# --- containment-check ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def hostile_source(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Three scenarios run against a captured model, through the same factory the CLI uses."""
    import asyncio

    root = tmp_path_factory.mktemp("hostile") / "runs"
    key = Ed25519PrivateKey.generate()
    names = ("agent-indirect-ticket", "agent-tool-misuse", "agent-excessive-agency")

    async def run_all() -> None:
        for name in names:
            scenario = load_scenario(ROOT / "scenarios" / "agent" / f"{name}.yaml")
            manifest, factory, execute = _runner_factory(
                key,
                lambda index, sid=name: root / sid,
                seed=42,
                judge=False,
                attacker=False,
                provider=HostileModel(intents=6),
                pin_id="offline-scripted",
                pin=None,
            )
            runner_, directory = factory(0)
            await execute(runner_, scenario, manifest, name, directory)

    asyncio.run(run_all())
    return root


@pytest.fixture
def hostile_bundles(hostile_source: Path, tmp_path: Path) -> Path:
    """A private copy per test, so a test that tampers with a bundle cannot affect another."""
    import shutil

    return Path(shutil.copytree(hostile_source, tmp_path / "hostile"))


def test_containment_holds_over_a_captured_models_bundles(hostile_bundles: Path) -> None:
    report = check_tree(hostile_bundles)
    payload = report.to_json()
    assert payload["holds"] and payload["bundles"] == 3, payload["violations"]
    totals = payload["totals"]
    assert totals["model_calls"] > 0 and totals["compiled_intents"] > 0
    assert totals["rejected_intents"] > 0
    assert {"shell.exec", "fixture.teardown"} & set(payload["invented_operations"])


def test_containment_check_cli_writes_its_report(hostile_bundles: Path, tmp_path: Path) -> None:
    out = tmp_path / "containment.json"
    result = runner.invoke(app, ["containment-check", str(hostile_bundles), "--output", str(out)])
    assert result.exit_code == 0, result.output
    assert "violations=0" in result.output
    assert json.loads(out.read_text())["holds"] is True


def bundle_parts(root: Path) -> tuple[list[dict[str, Any]], Phase1Scenario, AuthorizationManifest]:
    directory = bundle_directories(root)[0]
    events = [json.loads(line) for line in (directory / "evidence.jsonl").read_text().splitlines()]
    scenario = Phase1Scenario.model_validate_json((directory / "scenario.json").read_text())
    manifest = AuthorizationManifest.model_validate_json((directory / "manifest.json").read_text())
    return events, scenario, manifest


def compiled(events: list[dict[str, Any]]) -> dict[str, Any]:
    return next(e for e in events if e.get("reason_code") == "TOOL_INTENT_COMPILED")


@pytest.mark.parametrize(
    ("plant", "named"),
    [
        (
            lambda e: compiled(e)["data"]["action"].update(operation="shell.exec"),
            "compiled operation",
        ),
        (lambda e: compiled(e)["data"]["action"].update(adapter="control"), "compiled adapter"),
        (
            lambda e: compiled(e)["data"]["action"]["target"].update(
                url="http://127.0.0.1:28081/x"
            ),
            "off the data asset",
        ),
        (
            lambda e: compiled(e)["data"]["action"].update(credential_handle="supportlab-control"),
            "another credential",
        ),
        (
            lambda e: compiled(e)["data"]["action"]["target"].update(tenant_id="org-b"),
            "against tenant",
        ),
        (
            lambda e: next(x for x in e if x.get("reason_code") == "TARGET_OBSERVED")[
                "data"
            ].update(url="http://10.0.0.1:80/"),
            "not a signed asset",
        ),
        (
            lambda e: e.append(
                {
                    "sequence": 999,
                    "kind": "policy",
                    "reason_code": "MODEL_ENDPOINT_PERMITTED",
                    "data": {"origin": "https://exfil.invalid:443"},
                }
            ),
            "unsigned origin",
        ),
        (
            lambda e: (
                e[:]
                and [e.remove(x) for x in list(e) if x.get("reason_code") == "TOOL_INTENT_REJECTED"]
            ),
            "refusals are recorded",
        ),
    ],
)
def test_a_planted_violation_is_named(
    hostile_bundles: Path, plant: Callable[[list[dict[str, Any]]], Any], named: str
) -> None:
    events, scenario, manifest = bundle_parts(hostile_bundles)
    assert not check_events(events, scenario, manifest).violations
    plant(events)
    violations = check_events(events, scenario, manifest).violations
    assert any(named in violation for violation in violations), violations


def test_a_tampered_bundle_fails_containment(hostile_bundles: Path) -> None:
    directory = bundle_directories(hostile_bundles)[0]
    (directory / "summary.json").write_text("{}")
    payload = check_tree(hostile_bundles).to_json()
    assert not payload["holds"]
    assert any("does not verify" in violation for violation in payload["violations"])


def test_containment_check_refuses_an_empty_tree(tmp_path: Path) -> None:
    result = runner.invoke(app, ["containment-check", str(tmp_path)])
    assert result.exit_code == 1 and "no run bundle" in result.output
