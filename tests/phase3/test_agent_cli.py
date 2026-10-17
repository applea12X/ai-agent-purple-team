"""WP3.7 -- the agent lane's CLI surface, including the lane it refuses to run."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import httpx
import pytest
from typer.testing import CliRunner

from purpleloop import agent_cli
from purpleloop.adapters.model_provider import OpenAICompatibleProvider
from purpleloop.agent_cli import CREDENTIAL_ENV, ModelUnavailableForLane, networked_provider
from purpleloop.cli import app
from purpleloop.runtime.demo import ROOT

runner = CliRunner()
SCENARIO = ROOT / "scenarios" / "agent" / "agent-indirect-ticket.yaml"


def test_agent_run_completes_and_reports_the_four_numbers(tmp_path: Path) -> None:
    result = runner.invoke(app, ["agent-run", str(SCENARIO), str(tmp_path / "run")])
    assert result.exit_code == 0, result.output
    for name in ("attack_success", "clean_utility", "utility_under_attack", "side_effects"):
        assert name in result.output
    assert (tmp_path / "run" / "stochastic.json").exists()


def test_agent_run_refuses_to_overwrite_or_accept_a_bad_scenario(tmp_path: Path) -> None:
    missing = runner.invoke(app, ["agent-run", str(tmp_path / "nope.yaml"), str(tmp_path / "o")])
    assert missing.exit_code == 1 and "FAILED" in missing.output


def test_judge_report_writes_the_negative_control_beside_the_number(tmp_path: Path) -> None:
    result = runner.invoke(app, ["judge-report", "--output-dir", str(tmp_path / "judge")])
    assert result.exit_code == 0, result.output
    assert "resistance=" in result.output and "negative control" in result.output
    payload = (tmp_path / "judge" / "evaluator-redteam.json").read_text()
    assert "negative_control_without_delimiting" in payload
    # The stand-in is named in the artifact, so the number cannot be read as a model result.
    assert "not of any" in payload and "model's resistance" in payload


def test_a_hosted_model_without_a_credential_is_skipped_never_downgraded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv(CREDENTIAL_ENV, raising=False)
    with pytest.raises(ModelUnavailableForLane, match="skipped, not downgraded"):
        networked_provider("https://models.invalid/v1", "openai-compatible")


def test_the_stochastic_lane_exits_zero_when_it_is_skipped(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A skipped lane is a recorded skip, not a failure and not a silent offline run."""
    monkeypatch.delenv(CREDENTIAL_ENV, raising=False)
    result = runner.invoke(
        app,
        [
            "agent-run",
            str(SCENARIO),
            str(tmp_path / "skipped"),
            "--endpoint",
            "https://models.invalid/v1",
        ],
    )
    assert result.exit_code == 0
    assert "SKIPPED" in result.output
    assert not (tmp_path / "skipped").exists(), "a skipped lane must not write a bundle"


def test_a_local_profile_needs_no_credential(monkeypatch: pytest.MonkeyPatch) -> None:
    """Ollama and vLLM on a local socket are commonly unauthenticated; a hosted API is not."""
    monkeypatch.delenv(CREDENTIAL_ENV, raising=False)
    provider, pin = networked_provider("http://127.0.0.1:11434/v1", "ollama")
    assert pin.provider == "ollama"
    assert provider.endpoint == "http://127.0.0.1:11434"


def test_an_endpoint_with_an_api_path_is_signed_by_origin_and_called_at_its_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``--endpoint`` is a base URL with an API path; the manifest signs only its origin.

    Passing the base URL straight into the manifest was refused (a signed model asset carries no
    path), and dropping the path to satisfy the manifest sent requests where Ollama serves
    nothing. Neither form reached a model, and no test drove the CLI with a networked endpoint.
    """
    monkeypatch.delenv(CREDENTIAL_ENV, raising=False)
    requested: list[str] = []

    def respond(request: httpx.Request) -> httpx.Response:
        requested.append(str(request.url))
        return httpx.Response(
            200,
            json={
                "choices": [{"message": {"content": "Summary: nothing to do."}}],
                "usage": {"prompt_tokens": 10, "completion_tokens": 5},
            },
        )

    class StubbedProvider(OpenAICompatibleProvider):
        def __init__(self, **kwargs: Any) -> None:
            super().__init__(**kwargs, transport=httpx.MockTransport(respond))

    monkeypatch.setattr(agent_cli, "OpenAICompatibleProvider", StubbedProvider)
    out = tmp_path / "ollama"
    result = runner.invoke(
        app,
        [
            "agent-run",
            str(SCENARIO),
            str(out),
            "--endpoint",
            "http://127.0.0.1:11434/v1",
            "--profile",
            "ollama",
        ],
    )
    assert "FAILED" not in result.output, result.output
    assert "n=1" in result.output
    assert requested and all(
        url == "http://127.0.0.1:11434/v1/chat/completions" for url in requested
    )
    evidence = (out / SCENARIO.stem / "evidence.jsonl").read_text()
    assert "MODEL_ENDPOINT_PERMITTED" in evidence
    assert "MODEL_ENDPOINT_NOT_SIGNED" not in evidence
