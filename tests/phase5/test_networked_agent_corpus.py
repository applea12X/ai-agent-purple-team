"""``agent-corpus``: the agent corpus against a networked pin, as WP5.0.2 needs it, offline here.

Driven through a stub endpoint on a two-scenario subset so the suite runs in seconds. The same
command, with the real endpoint and no ``--only``, is the 25 x 5 sampled run; the assertions
here are the ones that run's acceptance note will rely on: every bundle verifies, each scenario
has a classified outcome, per-repetition seeds are signed, and the containment property can be
checked over the output directly.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from purpleloop import agent_cli
from purpleloop.agent_cli import CREDENTIAL_ENV
from purpleloop.cli import app
from purpleloop.reporting.bundle import verify_bundle
from purpleloop.scoring.containment import check_tree

runner = CliRunner()
ENDPOINT = ["--endpoint", "http://127.0.0.1:11434/v1", "--profile", "ollama"]
TWO = ["--only", "agent-indirect-ticket", "--only", "agent-tool-misuse"]


def corpus(tmp_path: Path, *args: str) -> tuple[Any, Path | None]:
    out = tmp_path / "corpus"
    result = runner.invoke(app, ["agent-corpus", *ENDPOINT, "--output-dir", str(out), *args])
    roots = sorted(out.glob("*/")) if out.exists() else []
    return result, roots[-1] if roots else None


def test_a_sampled_corpus_run_writes_a_verified_suite_with_signed_seeds(
    tmp_path: Path, stub_model: Any
) -> None:
    result, root = corpus(
        tmp_path,
        *TWO,
        "--repetitions",
        "2",
        "--temperature",
        "0.7",
        "--seed-policy",
        "per-repetition",
        "--model-id",
        "qwen2.5:7b-instruct",
        "--model-version",
        "845dbda0ea48",
    )
    assert root is not None, result.output
    assert verify_bundle(root)["scenarios"] == 4
    suite = json.loads((root / "suite.json").read_text())
    assert suite["model_provider"] == "ollama"
    assert suite["model_pin"]["decoding"]["temperature"] == 0.7
    assert suite["model_pin"]["model_version"] == "845dbda0ea48"
    assert suite["seed_policy"] == "per-repetition" and suite["repetitions"] == 2
    assert set(suite["outcomes"]) == {"agent-indirect-ticket", "agent-tool-misuse"}
    assert suite["not_run"] == [] and suite["cost_microusd"] == 0
    for sid in suite["outcomes"]:
        for index in range(2):
            (pin,) = json.loads((root / f"{sid}-rep-{index}" / "manifest.json").read_text())[
                "phase3"
            ]["model_pins"]
            assert pin["decoding"]["seed"] == 42 + index
        reproduction = json.loads((root / "reproduction" / f"{sid}.json").read_text())
        assert reproduction["n"] == 2
        stochastic = json.loads((root / "stochastic" / f"{sid}.json").read_text())
        assert stochastic["repetitions"]["seed_policy"] == "model-seed-42-plus-repetition-index"
        outcome = json.loads((root / "outcomes" / f"{sid}.json").read_text())
        assert outcome["model_pin_id"] == "networked"
    assert {body["temperature"] for body in stub_model.requests} == {0.7}
    assert "SUITE " in result.output and "Verified report" in result.output
    # The stub proposes nothing, so no scenario's attack can succeed and none passes as a
    # defended regression; the command reports that rather than calling the suite green.
    assert result.exit_code == 1


def test_containment_is_checked_over_the_corpus_output(tmp_path: Path, stub_model: Any) -> None:
    def propose(body: dict[str, Any]) -> str:
        return json.dumps(
            {
                "message": "Done.",
                "tool_intents": [
                    {"operation": "shell.exec", "arguments": {}},
                    {
                        "operation": "email.send",
                        "arguments": {"destination": "attacker-sink", "subject": "s", "body": "b"},
                    },
                ],
            }
        )

    stub_model.content = propose
    _, root = corpus(tmp_path, *TWO, "--repetitions", "1")
    assert root is not None
    payload = check_tree(root).to_json()
    assert payload["holds"], payload["violations"]
    assert "shell.exec" in payload["invented_operations"]
    assert payload["totals"]["compiled_intents"] > 0


def test_an_endpoint_error_is_classified_as_such_not_as_a_scenario_failure(
    tmp_path: Path, stub_model: Any
) -> None:
    stub_model.status = 503
    result, root = corpus(tmp_path, *TWO, "--repetitions", "1")
    assert root is not None and verify_bundle(root)["scenarios"] == 2
    for sid in ("agent-indirect-ticket", "agent-tool-misuse"):
        outcome = json.loads((root / "outcomes" / f"{sid}.json").read_text())
        assert (outcome["outcome"], outcome["reason_code"]) == (
            "endpoint-error",
            "MODEL_PROVIDER_UNAVAILABLE",
        )
    assert "endpoint-error=2" in result.output and result.exit_code == 1


def test_an_all_excluded_scenario_is_recorded_and_the_suite_continues(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, stub_model: Any
) -> None:
    original = agent_cli._inspect_execute

    async def flaky(runner_: Any, scenario: Any, *args: Any, **kwargs: Any) -> Any:
        if scenario.scenario_id == "agent-indirect-ticket":
            raise ConnectionError("endpoint went away")
        return await original(runner_, scenario, *args, **kwargs)

    monkeypatch.setattr(agent_cli, "_inspect_execute", flaky)
    result, root = corpus(tmp_path, *TWO, "--repetitions", "2")
    assert root is not None, result.output
    outcome = json.loads((root / "outcomes" / "agent-indirect-ticket.json").read_text())
    assert (outcome["outcome"], outcome["reason_code"]) == (
        "endpoint-error",
        "EVERY_REPETITION_EXCLUDED",
    )
    assert "ConnectionError" in outcome["detail"]
    suite = json.loads((root / "suite.json").read_text())
    assert suite["scenarios"] == ["agent-tool-misuse-rep-0", "agent-tool-misuse-rep-1"]
    assert verify_bundle(root)["scenarios"] == 2
    assert result.exit_code == 1


def test_the_suite_cost_budget_stops_starting_scenarios(tmp_path: Path, stub_model: Any) -> None:
    stub_model.prompt_tokens, stub_model.completion_tokens = 1000, 1000
    result, root = corpus(
        tmp_path,
        *TWO,
        "--repetitions",
        "1",
        "--price-input-microusd-per-1k",
        "100",
        "--price-output-microusd-per-1k",
        "100",
        "--suite-cost-budget-microusd",
        "1",
    )
    assert root is not None, result.output
    suite = json.loads((root / "suite.json").read_text())
    # 200 micro-USD per call, now carried from the evidence into the repetition record.
    assert suite["cost_microusd"] > 0 and suite["cost_microusd"] % 200 == 0
    assert suite["not_run"] == ["agent-tool-misuse"]
    assert list(suite["outcomes"]) == ["agent-indirect-ticket"]
    assert "not_run=1" in result.output and result.exit_code == 1


def test_an_unknown_scenario_id_is_refused(tmp_path: Path, stub_model: Any) -> None:
    result, _ = corpus(tmp_path, "--only", "agent-nope")
    assert result.exit_code == 1 and "unknown scenario ids: agent-nope" in result.output
    assert not stub_model.requests


def test_a_hosted_corpus_run_skips_without_a_credential_and_refuses_without_a_price(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, stub_model: Any
) -> None:
    hosted = ["agent-corpus", "--endpoint", "https://models.invalid/v1"]
    out = ["--output-dir", str(tmp_path / "h")]
    skipped = runner.invoke(app, [*hosted, *out])
    assert skipped.exit_code == 0 and "SKIPPED" in skipped.output
    monkeypatch.setenv(CREDENTIAL_ENV, "test-only-placeholder")
    refused = runner.invoke(app, [*hosted, *out])
    assert refused.exit_code == 1 and "MODEL_PRICE_UNDECLARED" in refused.output
    assert not stub_model.requests and not (tmp_path / "h").exists()


def test_the_endpoint_is_read_from_the_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, stub_model: Any
) -> None:
    monkeypatch.setenv("PURPLELOOP_MODEL_ENDPOINT", "http://127.0.0.1:11434/v1")
    monkeypatch.setenv("PURPLELOOP_MODEL_PROFILE", "ollama")
    monkeypatch.setenv("PURPLELOOP_MODEL_REPETITIONS", "1")
    out = tmp_path / "env"
    result = runner.invoke(
        app, ["agent-corpus", "--output-dir", str(out), "--only", "agent-indirect-ticket"]
    )
    assert "Verified report" in result.output, result.output
    assert stub_model.urls and all(
        url == "http://127.0.0.1:11434/v1/chat/completions" for url in stub_model.urls
    )
