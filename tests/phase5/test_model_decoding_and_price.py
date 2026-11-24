"""Model-plane knobs for real-model runs: decoding, price, seed policy, and the signed cost cap.

The defaults are pinned against the inline construction they replaced, so no recorded hash moves;
every override is shown landing in the request, the signed pin, and the MODEL_CALLED record; and
the price rules are shown to fail closed. The cost cap is driven end to end through the CLI with a
stub endpoint and is paired with a control run, so a cap that never fires cannot pass.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from purpleloop.adapters.agent import SYSTEM_PROMPT_HASH
from purpleloop.agent_cli import (
    CREDENTIAL_ENV,
    SeedPolicy,
    networked_provider,
    resolve_cost_budget,
    resolve_seed_policy,
)
from purpleloop.cli import app
from purpleloop.control.model_config import (
    JUDGE_ENV,
    ModelConfigError,
    ModelPriceUndeclared,
    ModelSettings,
    build_pin,
    resolve_decoding,
    resolve_price,
    with_seed,
)
from purpleloop.runtime.demo import ROOT
from purpleloop.schemas.phase3 import DecodingParameters, ModelPin

runner = CliRunner()
SCENARIO = ROOT / "scenarios" / "agent" / "agent-indirect-ticket.yaml"
OLLAMA = ["--endpoint", "http://127.0.0.1:11434/v1", "--profile", "ollama"]
Events = Callable[[Path], list[dict[str, Any]]]


def run(*args: str) -> Any:
    return runner.invoke(app, ["agent-run", str(SCENARIO), *args])


def model_calls(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        event["data"]["call"]
        for event in events
        if event["kind"] == "model" and event["reason_code"] == "MODEL_CALLED"
    ]


# --- defaults are the old pin, exactly -----------------------------------------------------------


def test_the_default_networked_pin_is_byte_identical_to_the_inline_one() -> None:
    """With nothing configured the pin is what ``DecodingParameters(seed=42)`` produced."""
    _, pin = networked_provider("http://127.0.0.1:11434/v1", "ollama")
    legacy = ModelPin(
        pin_id="networked",
        provider="ollama",
        model_id="unspecified-model",
        model_version=None,
        decoding=DecodingParameters(seed=42),
        system_prompt_hash=SYSTEM_PROMPT_HASH,
    )
    assert pin == legacy
    assert pin.canonical_bytes() == legacy.canonical_bytes()
    assert pin.decoding == DecodingParameters(temperature=0.0, top_p=1.0, seed=42)
    assert pin.decoding.max_output_tokens == 512


def test_the_offline_run_is_unchanged_by_the_new_options(
    tmp_path: Path, read_events: Events
) -> None:
    result = run(str(tmp_path / "offline"))
    assert result.exit_code == 0, result.output
    calls = model_calls(read_events(tmp_path / "offline" / SCENARIO.stem))
    assert calls
    for call in calls:
        assert call["decoding"] == {
            "temperature": 0.0,
            "top_p": 1.0,
            "max_output_tokens": 512,
            "seed": 42,
        }
        assert call["provider"] == "offline"


# --- decoding resolution ---------------------------------------------------------------------


def test_environment_sets_decoding_and_the_command_line_wins() -> None:
    env = {
        "PURPLELOOP_MODEL_TEMPERATURE": "0.7",
        "PURPLELOOP_MODEL_TOP_P": "0.9",
        "PURPLELOOP_MODEL_SEED": "7",
        "PURPLELOOP_MODEL_MAX_OUTPUT_TOKENS": "1024",
    }
    from_env = resolve_decoding(ModelSettings(), env=env)
    assert from_env == DecodingParameters(
        temperature=0.7, top_p=0.9, seed=7, max_output_tokens=1024
    )
    overridden = resolve_decoding(
        ModelSettings(temperature=0.2, top_p=0.5, seed="9", max_output_tokens=64), env=env
    )
    assert overridden == DecodingParameters(
        temperature=0.2, top_p=0.5, seed=9, max_output_tokens=64
    )


def test_an_empty_variable_is_unset_and_none_means_unseeded() -> None:
    assert resolve_decoding(ModelSettings(), env={"PURPLELOOP_MODEL_TEMPERATURE": ""}) == (
        DecodingParameters(seed=42)
    )
    unseeded = resolve_decoding(ModelSettings(), env={"PURPLELOOP_MODEL_SEED": "None"})
    assert unseeded.seed is None


def test_the_judge_reads_its_own_variables() -> None:
    env = {"PURPLELOOP_JUDGE_TEMPERATURE": "0.3", "PURPLELOOP_MODEL_TEMPERATURE": "0.9"}
    assert resolve_decoding(ModelSettings(), names=JUDGE_ENV, env=env).temperature == 0.3


@pytest.mark.parametrize(
    "env",
    [
        {"PURPLELOOP_MODEL_TEMPERATURE": "hot"},
        {"PURPLELOOP_MODEL_TEMPERATURE": "2.5"},
        {"PURPLELOOP_MODEL_TOP_P": "1.5"},
        {"PURPLELOOP_MODEL_SEED": "-1"},
        {"PURPLELOOP_MODEL_SEED": "seven"},
        {"PURPLELOOP_MODEL_MAX_OUTPUT_TOKENS": "0"},
        {"PURPLELOOP_MODEL_MAX_OUTPUT_TOKENS": "1.5"},
    ],
)
def test_malformed_decoding_is_refused_not_clamped(env: dict[str, str]) -> None:
    with pytest.raises(ModelConfigError):
        resolve_decoding(ModelSettings(), env=env)


def test_per_repetition_seed_overflow_is_refused() -> None:
    _, pin = networked_provider("http://127.0.0.1:11434/v1", "ollama")
    with pytest.raises(ModelConfigError, match="seed out of range"):
        with_seed(pin, 2**32)
    assert with_seed(pin, 43).decoding.seed == 43


def test_a_non_networked_profile_cannot_build_a_networked_pin() -> None:
    with pytest.raises(ModelConfigError, match="not a networked provider"):
        build_pin(
            pin_id="p",
            profile="offline",
            system_prompt_hash=SYSTEM_PROMPT_HASH,
            settings=ModelSettings(),
        )


# --- price: a hosted run never records a silent zero ----------------------------------------------


def test_a_local_profile_defaults_to_zero_and_may_declare_a_price() -> None:
    assert resolve_price("ollama", "m", ModelSettings(), env={}) == (0, 0)
    assert resolve_price(
        "vllm",
        "m",
        ModelSettings(),
        env={
            "PURPLELOOP_MODEL_PRICE_INPUT_MICROUSD_PER_1K": "5",
            "PURPLELOOP_MODEL_PRICE_OUTPUT_MICROUSD_PER_1K": "6",
        },
    ) == (5, 6)


def test_a_hosted_profile_without_a_price_is_refused() -> None:
    with pytest.raises(ModelPriceUndeclared, match="refusing rather than recording"):
        resolve_price("openai-compatible", "gpt-x", ModelSettings(), env={})


def test_a_hosted_zero_price_needs_the_named_acknowledgement() -> None:
    zero = ModelSettings(price_input_microusd_per_1k=0, price_output_microusd_per_1k=0)
    with pytest.raises(ModelPriceUndeclared):
        resolve_price("openai-compatible", "gpt-x", zero, env={})
    free = ModelSettings(declared_free="gpt-x")
    assert resolve_price("openai-compatible", "gpt-x", free, env={}) == (0, 0)


def test_an_acknowledgement_for_another_model_does_not_carry_over() -> None:
    with pytest.raises(ModelPriceUndeclared, match="covers only the model it names"):
        resolve_price("openai-compatible", "gpt-y", ModelSettings(declared_free="gpt-x"), env={})


def test_priced_and_declared_free_at_once_is_contradictory() -> None:
    settings = ModelSettings(
        declared_free="gpt-x", price_input_microusd_per_1k=1, price_output_microusd_per_1k=2
    )
    with pytest.raises(ModelPriceUndeclared, match="both priced and declared free"):
        resolve_price("openai-compatible", "gpt-x", settings, env={})


def test_half_a_price_is_refused() -> None:
    with pytest.raises(ModelPriceUndeclared, match="or neither"):
        resolve_price(
            "openai-compatible",
            "gpt-x",
            ModelSettings(),
            env={"PURPLELOOP_MODEL_PRICE_INPUT_MICROUSD_PER_1K": "150"},
        )


def test_a_negative_or_malformed_price_is_refused() -> None:
    with pytest.raises(ModelConfigError, match="negative"):
        resolve_price(
            "ollama",
            "m",
            ModelSettings(price_input_microusd_per_1k=-1, price_output_microusd_per_1k=1),
            env={},
        )
    with pytest.raises(ModelConfigError, match="integer"):
        resolve_price(
            "ollama",
            "m",
            ModelSettings(),
            env={
                "PURPLELOOP_MODEL_PRICE_INPUT_MICROUSD_PER_1K": "1.5",
                "PURPLELOOP_MODEL_PRICE_OUTPUT_MICROUSD_PER_1K": "1",
            },
        )


def test_a_hosted_price_lands_on_the_pin(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(CREDENTIAL_ENV, "test-only-placeholder")
    monkeypatch.setenv("PURPLELOOP_MODEL_PRICE_INPUT_MICROUSD_PER_1K", "150")
    monkeypatch.setenv("PURPLELOOP_MODEL_PRICE_OUTPUT_MICROUSD_PER_1K", "600")
    _, pin = networked_provider("https://models.invalid/v1", "openai-compatible")
    assert (pin.price_input_microusd_per_1k, pin.price_output_microusd_per_1k) == (150, 600)
    assert pin.cost_microusd(1000, 1000) == 750


def test_the_hosted_lane_refuses_an_unpriced_run_and_writes_no_bundle(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, stub_model: Any
) -> None:
    """With a credential but no price the run is a failure, not a skip and not a zero."""
    monkeypatch.setenv(CREDENTIAL_ENV, "test-only-placeholder")
    out = tmp_path / "hosted"
    result = run(str(out), "--endpoint", "https://models.invalid/v1")
    assert result.exit_code == 1
    assert "MODEL_PRICE_UNDECLARED" in result.output
    assert not stub_model.requests, "no model call may happen before the price is declared"
    assert not out.exists()


def test_a_missing_credential_is_still_a_skip_before_the_price_is_checked(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv(CREDENTIAL_ENV, raising=False)
    result = run(str(tmp_path / "s"), "--endpoint", "https://models.invalid/v1")
    assert result.exit_code == 0 and "skip-no-credential" in result.output


def test_a_model_option_on_an_offline_run_is_refused(tmp_path: Path) -> None:
    result = run(str(tmp_path / "o"), "--temperature", "0.7")
    assert result.exit_code == 1
    assert "need --endpoint" in result.output


# --- the chosen values land in the request, the signed pin, and every model record ----------------


def test_sampled_decoding_lands_in_the_request_the_manifest_and_the_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, stub_model: Any, read_events: Events
) -> None:
    monkeypatch.setenv("PURPLELOOP_MODEL_TOP_P", "0.95")
    monkeypatch.setenv("PURPLELOOP_MODEL_TEMPERATURE", "0.1")  # overridden on the command line
    out = tmp_path / "sampled"
    result = run(
        str(out),
        *OLLAMA,
        "--temperature",
        "0.7",
        "--model-seed",
        "7",
        "--max-output-tokens",
        "256",
        "--model-id",
        "qwen2.5:7b-instruct",
        "--model-version",
        "845dbda0ea48",
    )
    assert "FAILED" not in result.output, result.output
    expected = {"temperature": 0.7, "top_p": 0.95, "max_output_tokens": 256, "seed": 7}
    assert stub_model.requests
    for body in stub_model.requests:
        assert body["temperature"] == 0.7 and body["top_p"] == 0.95
        assert body["seed"] == 7 and body["max_tokens"] == 256
        assert body["model"] == "qwen2.5:7b-instruct"
    bundle = out / SCENARIO.stem
    (pin,) = json.loads((bundle / "manifest.json").read_text())["phase3"]["model_pins"]
    assert pin["decoding"] == expected
    assert pin["model_version"] == "845dbda0ea48"
    calls = model_calls(read_events(bundle))
    assert calls and all(call["decoding"] == expected for call in calls)
    assert all(call["reproducible_pin"] for call in calls)


def test_an_unseeded_pin_is_recorded_as_not_reproducible(
    tmp_path: Path, stub_model: Any, read_events: Events
) -> None:
    out = tmp_path / "unseeded"
    result = run(str(out), *OLLAMA, "--model-seed", "none", "--model-version", "v")
    assert "FAILED" not in result.output, result.output
    assert all("seed" not in body for body in stub_model.requests)
    calls = model_calls(read_events(out / SCENARIO.stem))
    assert calls and not any(call["reproducible_pin"] for call in calls)


# --- seed policy -------------------------------------------------------------------------------


def test_per_repetition_seeding_gives_each_repetition_its_own_signed_seed(
    tmp_path: Path, stub_model: Any, read_events: Events
) -> None:
    """Under sampling a fixed seed repeats one reply; per-repetition seeding measures variance."""
    out = tmp_path / "seeded"
    result = run(
        str(out),
        *OLLAMA,
        "--repetitions",
        "3",
        "--temperature",
        "0.7",
        "--seed-policy",
        "per-repetition",
    )
    assert "FAILED" not in result.output, result.output
    seen_by_rep: list[set[int]] = []
    for index in range(3):
        bundle = out / f"{SCENARIO.stem}-rep-{index}"
        (pin,) = json.loads((bundle / "manifest.json").read_text())["phase3"]["model_pins"]
        assert pin["decoding"]["seed"] == 42 + index
        seen_by_rep.append({call["decoding"]["seed"] for call in model_calls(read_events(bundle))})
    assert seen_by_rep == [{42}, {43}, {44}]
    # The request seeds follow the same sequence, repetition by repetition.
    assert sorted({body["seed"] for body in stub_model.requests}) == [42, 43, 44]
    stochastic = json.loads((out / "stochastic.json").read_text())
    assert stochastic["repetitions"]["seed_policy"] == "model-seed-42-plus-repetition-index"


def test_a_fixed_seed_policy_keeps_the_earlier_label(tmp_path: Path, stub_model: Any) -> None:
    out = tmp_path / "fixed"
    result = run(str(out), *OLLAMA, "--repetitions", "2")
    assert "FAILED" not in result.output, result.output
    assert {body["seed"] for body in stub_model.requests} == {42}
    stochastic = json.loads((out / "stochastic.json").read_text())
    assert stochastic["repetitions"]["seed_policy"] == "fixed-per-repetition"


def test_per_repetition_seeding_without_a_seed_is_refused(tmp_path: Path, stub_model: Any) -> None:
    result = run(
        str(tmp_path / "x"), *OLLAMA, "--model-seed", "none", "--seed-policy", "per-repetition"
    )
    assert result.exit_code == 1 and "needs a seeded" in result.output
    assert not stub_model.requests


def test_seed_policy_and_cost_budget_read_the_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    assert resolve_seed_policy(None) == SeedPolicy.FIXED
    monkeypatch.setenv("PURPLELOOP_MODEL_SEED_POLICY", "per-repetition")
    assert resolve_seed_policy(None) == SeedPolicy.PER_REPETITION
    assert resolve_seed_policy(SeedPolicy.FIXED) == SeedPolicy.FIXED
    monkeypatch.setenv("PURPLELOOP_MODEL_SEED_POLICY", "sometimes")
    with pytest.raises(ModelConfigError):
        resolve_seed_policy(None)
    assert resolve_cost_budget(None) == 1_000_000
    monkeypatch.setenv("PURPLELOOP_MODEL_COST_BUDGET_MICROUSD", "2500")
    assert resolve_cost_budget(None) == 2500
    assert resolve_cost_budget(10) == 10
    monkeypatch.setenv("PURPLELOOP_MODEL_COST_BUDGET_MICROUSD", "lots")
    with pytest.raises(ModelConfigError):
        resolve_cost_budget(None)


# --- the signed cost cap fires -------------------------------------------------------------------


def priced(*args: str) -> list[str]:
    # 1,000 + 1,000 tokens per call at 100 + 100 micro-USD per 1k: exactly 200 micro-USD a call.
    return [
        *OLLAMA,
        "--price-input-microusd-per-1k",
        "100",
        "--price-output-microusd-per-1k",
        "100",
        *args,
    ]


def test_the_signed_cost_cap_stops_a_run_when_price_times_tokens_exceeds_it(
    tmp_path: Path, stub_model: Any, read_events: Events
) -> None:
    stub_model.prompt_tokens = 1000
    stub_model.completion_tokens = 1000
    out = tmp_path / "capped"
    result = run(str(out), *priced("--cost-budget-microusd", "500"))
    bundle = out / SCENARIO.stem
    manifest = json.loads((bundle / "manifest.json").read_text())
    assert manifest["phase3"]["cost_microusd_budget"] == 500
    assert manifest["budgets"]["cost_microusd"] == 500
    events = read_events(bundle)
    calls = model_calls(events)
    # Two calls fit under 500; the third is charged, refused, and fails its action closed.
    assert len(calls) == 2 and sum(call["cost_microusd"] for call in calls) == 400
    assert len(stub_model.requests) == 3
    assert any("cost_microusd budget exhausted" in json.dumps(event) for event in events)
    assert result.exit_code == 1, result.output
    # A cap that fired is a budget stop, not a scenario failure: the vocabulary keeps them apart.
    outcome = json.loads((out / "outcome.json").read_text())
    assert (outcome["outcome"], outcome["reason_code"]) == ("budget-stop", "BUDGET_EXCEEDED")


def test_the_same_run_under_the_default_cap_is_not_stopped(
    tmp_path: Path, stub_model: Any, read_events: Events
) -> None:
    """The control: a cap test that passes whether or not the cap fires measures nothing."""
    stub_model.prompt_tokens = 1000
    stub_model.completion_tokens = 1000
    out = tmp_path / "uncapped"
    result = run(str(out), *priced())
    events = read_events(out / SCENARIO.stem)
    calls = model_calls(events)
    assert len(calls) == len(stub_model.requests) > 2
    assert all(call["cost_microusd"] == 200 for call in calls)
    assert not any("budget exhausted" in json.dumps(event) for event in events)
    assert "FAILED" not in result.output, result.output
