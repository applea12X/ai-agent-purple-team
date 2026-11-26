"""WP5.0.5 mechanism: ``judge-report`` against a networked judge, offline, through a stub endpoint.

The stub plays three judges whose agreement is known in advance -- one that answers every case
with its adjudicated label, one that always says ``false``, and a thinking model whose answer
follows a ``<think>`` block -- so the reported alpha, kappa, swap consistency, and critical false
passes can be checked against what they must be, and a faked figure fails. The frozen corpus
digest, the signed model endpoint, the price rules, and the signed budget are each shown to hold.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from ipaddress import ip_address
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from typer.testing import CliRunner

from purpleloop import agent_cli
from purpleloop.adapters.networked_judge import (
    JUDGE_SYSTEM_PROMPT,
    JUDGE_SYSTEM_PROMPT_HASH,
    UNPARSEABLE,
    ModelEndpointDenied,
    ModelEndpointRebound,
    ModelPlaneGuard,
    parse_verdict,
)
from purpleloop.cli import app
from purpleloop.control.manifest import ManifestVerifier
from purpleloop.judge_report import JUDGE_CREDENTIAL_ENV, JudgeRunConfig, judge_pin, trial_pin
from purpleloop.runtime.supportlab import KEY_ID, supportlab_agent_manifest
from purpleloop.schemas.action import TargetObservation
from purpleloop.scoring.evaluator_redteam import (
    FROZEN_CORPUS_DIGEST,
    CorpusDigestMismatch,
    agreement,
    load_corpus,
    pooled_agreement,
    require_frozen,
    resistance,
    resistance_from,
    run_trial,
    trial_agreement,
)
from purpleloop.scoring.judge import HybridJudge, ScriptedJudge

runner = CliRunner()
CORPUS = load_corpus(agent_cli.REDTEAM)
JUDGE = ["judge-report", "--judge-endpoint", "http://127.0.0.1:11434/v1", "--judge-profile"]
ESCAPE = str.maketrans({"<": "&lt;", ">": "&gt;"})


def case_for(prompt: str) -> Any:
    """The corpus case a rendered prompt was built from: every item body appears in it."""
    matches = [
        case
        for case in CORPUS.cases
        if case.rubric_id
        and all(item.body[:1200].translate(ESCAPE) in prompt for item in case.items)
    ]
    return max(matches, key=lambda case: sum(len(item.body) for item in case.items))


def user_prompt(body: dict[str, Any]) -> str:
    return str(body["messages"][1]["content"])


def oracle_reply(body: dict[str, Any]) -> str:
    case = case_for(user_prompt(body))
    ids = re.findall(r'id="([^"]+)"', user_prompt(body))
    return json.dumps({"verdict": case.label, "cited_evidence_ids": ids[:1], "confidence": 0.9})


def always_false(body: dict[str, Any]) -> str:
    ids = re.findall(r'id="([^"]+)"', user_prompt(body))
    return json.dumps({"verdict": "false", "cited_evidence_ids": ids[:1], "confidence": 0.5})


def judge_report(tmp_path: Path, *args: str) -> tuple[Any, dict[str, Any]]:
    out = tmp_path / "judge"
    result = runner.invoke(app, [*JUDGE, "ollama", "--output-dir", str(out), *args])
    path = out / "evaluator-redteam.json"
    return result, json.loads(path.read_text()) if path.exists() else {}


# --- the figures are the figures ----------------------------------------------------------------


def test_a_judge_that_matches_every_label_reports_perfect_agreement(
    tmp_path: Path, stub_judge: Any
) -> None:
    stub_judge.content = oracle_reply
    result, payload = judge_report(tmp_path)
    assert result.exit_code == 0, result.output
    agreement_ = payload["agreement"]
    assert agreement_["n"] == 24 and agreement_["krippendorff_alpha"] == 1.0
    assert agreement_["order_swap_consistency"] == 1.0 and agreement_["order_swap_trials"] == 24
    assert agreement_["kappa_n"] == 14 and agreement_["cohen_kappa"] == 1.0
    assert agreement_["abstentions"] == 10
    assert payload["hardened"]["resistance"] == 1.0
    assert payload["hardened"]["critical_false_passes"] == []
    # Three calls per case: delimited, swapped, and the undelimited negative control.
    assert payload["model_calls"]["calls"] == len(stub_judge.requests) == 72
    assert payload["corpus_digest"] == FROZEN_CORPUS_DIGEST
    assert "alpha=1.000" in result.output and "n=24" in result.output


def test_a_judge_that_always_says_false_is_reported_as_such(
    tmp_path: Path, stub_judge: Any
) -> None:
    """The faked-metric check: a useless judge cannot report a useful number."""
    stub_judge.content = always_false
    result, payload = judge_report(tmp_path)
    assert result.exit_code == 0, result.output  # advisory: completion is not a verdict
    hardened = payload["hardened"]
    assert hardened["resisted"] == 7  # exactly the seven cases adjudicated false
    true_cases = sorted(case.case_id for case in CORPUS.cases if case.label == "true")
    assert sorted(hardened["critical_false_passes"]) == true_cases
    assert payload["agreement"]["krippendorff_alpha"] < 0.2
    assert payload["provenance"] == "advisory"


def test_the_figures_match_the_phase3_functions_for_a_deterministic_judge() -> None:
    """``run_trial`` shares one delimited call between both metrics and changes no number."""
    trial = run_trial(HybridJudge(ScriptedJudge()), CORPUS, negative_control=True)
    assert resistance_from(CORPUS, trial.verdicts) == resistance(
        HybridJudge(ScriptedJudge()), CORPUS
    )
    assert trial.undelimited is not None
    assert resistance_from(CORPUS, trial.undelimited) == resistance(
        HybridJudge(ScriptedJudge()), CORPUS, delimit=False
    )
    assert trial_agreement(CORPUS, trial) == agreement(HybridJudge(ScriptedJudge()), CORPUS)
    pooled = pooled_agreement(CORPUS, [trial, trial])
    assert pooled.n == 48
    assert pooled.krippendorff_alpha == trial_agreement(CORPUS, trial).krippendorff_alpha


def test_trials_run_under_successive_seeds_and_pool_with_their_n(
    tmp_path: Path, stub_judge: Any
) -> None:
    stub_judge.content = oracle_reply
    result, payload = judge_report(
        tmp_path, "--trials", "2", "--no-negative-control", "--judge-temperature", "0.6"
    )
    assert result.exit_code == 0, result.output
    assert [trial["seed"] for trial in payload["trials"]] == [42, 43]
    assert {body["seed"] for body in stub_judge.requests} == {42, 43}
    assert {body["temperature"] for body in stub_judge.requests} == {0.6}
    assert len(stub_judge.requests) == 2 * 24 * 2  # no negative-control calls
    assert "negative_control_without_delimiting" not in payload
    assert payload["pooled_agreement"]["n"] == 48
    manifests = sorted((tmp_path / "judge" / "manifests").glob("trial-*.json"))
    assert len(manifests) == 2
    seeds = [
        next(
            pin["decoding"]["seed"]
            for pin in json.loads(path.read_text())["phase3"]["model_pins"]
            if pin["pin_id"] == "networked-judge"
        )
        for path in manifests
    ]
    assert seeds == [42, 43]
    assert "pooled alpha=1.000 n=48" in result.output


def test_the_judge_has_its_own_pin_prompt_and_record(tmp_path: Path, stub_judge: Any) -> None:
    stub_judge.content = oracle_reply
    _, payload = judge_report(
        tmp_path,
        "--judge-model-id",
        "deepseek-r1:latest",
        "--judge-model-version",
        "abc123",
        "--trials",
        "1",
    )
    pin = payload["judge_pin"]
    assert pin["pin_id"] == "networked-judge"
    assert pin["model_id"] == "deepseek-r1:latest" and pin["model_version"] == "abc123"
    assert pin["system_prompt_hash"] == JUDGE_SYSTEM_PROMPT_HASH
    assert all(
        body["messages"][0]["content"] == JUDGE_SYSTEM_PROMPT for body in stub_judge.requests
    )
    records = payload["model_calls"]["records"]
    assert records and {record["pin_id"] for record in records} == {"networked-judge"}
    assert {record["model_id"] for record in records} == {"deepseek-r1:latest"}
    authorization = payload["authorization"]
    assert authorization["permitted"] == 72 and authorization["denied"] == 0
    assert authorization["origins"] == ["http://127.0.0.1:11434"]
    (manifest,) = (tmp_path / "judge" / "manifests").glob("*.json")
    grants = json.loads(manifest.read_text())["phase3"]
    assert grants["judge_enabled"] and grants["judge_model_pin"] == "networked-judge"
    assert grants["model_assets"] == ["http://127.0.0.1:11434"]


# --- thinking models ----------------------------------------------------------------------------


def test_a_thinking_judge_is_parsed_after_its_reasoning_and_the_stripping_recorded(
    tmp_path: Path, stub_judge: Any
) -> None:
    def thinking(body: dict[str, Any]) -> str:
        # The reasoning mentions a verdict of its own, which must not be parsed as the answer.
        return '<think>Maybe {"verdict": "false"}? Let me check.</think>\n' + oracle_reply(body)

    stub_judge.content = thinking
    result, payload = judge_report(tmp_path)
    assert result.exit_code == 0, result.output
    assert payload["agreement"]["krippendorff_alpha"] == 1.0
    notes = payload["thinking"]
    assert notes["stripped"] == 72 and notes["unparseable_replies"] == 0
    assert all(
        set(note) == {"call", "stripped", "chars", "digest", "answer_remaining"}
        for note in notes["notes"]
    )
    assert "Let me check" not in json.dumps(payload)  # digest and size only, never the text


def test_a_judge_that_only_thinks_abstains(tmp_path: Path, stub_judge: Any) -> None:
    stub_judge.content = "<think>I ran out of tokens while deliberating"
    _, payload = judge_report(tmp_path, "--no-negative-control")
    assert payload["agreement"]["abstentions"] == 24
    assert payload["thinking"]["unparseable_replies"] == 48
    assert payload["hardened"]["critical_false_passes"] == []


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ('{"verdict": "TRUE", "cited_evidence_ids": ["e1"], "confidence": 0.8}', "true"),
        ('Here you go:\n```json\n{"verdict": "false", "cited_evidence_ids": ["e2"]}\n```', "false"),
        ('Answer: {"verdict": "abstain"} done', "abstain"),
        ("no json at all", UNPARSEABLE),
        ('["not", "an", "object"]', UNPARSEABLE),
        ('{"verdict": 3}', UNPARSEABLE),
    ],
)
def test_the_verdict_parser_never_repairs_a_reply_into_a_verdict(text: str, expected: str) -> None:
    verdict, _, _ = parse_verdict(text)
    assert verdict == expected


def test_malformed_confidence_and_citations_are_neutralised() -> None:
    assert parse_verdict('{"verdict": "true", "cited_evidence_ids": "e1", "confidence": "x"}') == (
        "true",
        (),
        0.0,
    )
    assert parse_verdict('{"verdict": "true", "confidence": NaN}')[2] == 0.0


# --- the corpus, the endpoint, the price, and the budget hold ------------------------------------


def test_a_changed_corpus_is_refused(tmp_path: Path) -> None:
    changed = tmp_path / "cases.json"
    changed.write_text(agent_cli.REDTEAM.read_text().replace('"true"', '"false"', 1))
    with pytest.raises(CorpusDigestMismatch):
        require_frozen(load_corpus(changed))
    assert require_frozen(CORPUS) is CORPUS


def test_judge_report_refuses_a_changed_corpus_on_both_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, stub_judge: Any
) -> None:
    changed = tmp_path / "cases.json"
    changed.write_text(agent_cli.REDTEAM.read_text() + "\n")
    monkeypatch.setattr(agent_cli, "REDTEAM", changed)
    scripted = runner.invoke(app, ["judge-report", "--output-dir", str(tmp_path / "s")])
    assert scripted.exit_code == 1 and "frozen" in scripted.output
    networked, _ = judge_report(tmp_path)
    assert networked.exit_code == 1 and "EVALUATOR_CORPUS_CHANGED" in networked.output
    assert not stub_judge.requests


def test_a_hosted_judge_without_a_credential_is_skipped(tmp_path: Path, stub_judge: Any) -> None:
    out = tmp_path / "hosted"
    result = runner.invoke(
        app,
        ["judge-report", "--judge-endpoint", "https://judge.invalid/v1", "--output-dir", str(out)],
    )
    assert result.exit_code == 0 and "SKIPPED" in result.output
    assert not stub_judge.requests and not out.exists()


def test_a_hosted_judge_without_a_price_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, stub_judge: Any
) -> None:
    monkeypatch.setenv(JUDGE_CREDENTIAL_ENV, "test-only-placeholder")
    result = runner.invoke(
        app,
        [
            "judge-report",
            "--judge-endpoint",
            "https://judge.invalid/v1",
            "--output-dir",
            str(tmp_path / "hosted"),
        ],
    )
    assert result.exit_code == 1 and "MODEL_PRICE_UNDECLARED" in result.output
    assert not stub_judge.requests


def test_the_signed_judge_budget_stops_the_report_and_keeps_what_ran(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, stub_judge: Any
) -> None:
    stub_judge.content = oracle_reply
    stub_judge.prompt_tokens = 1000
    stub_judge.completion_tokens = 0
    monkeypatch.setenv("PURPLELOOP_JUDGE_PRICE_INPUT_MICROUSD_PER_1K", "10")
    monkeypatch.setenv("PURPLELOOP_JUDGE_PRICE_OUTPUT_MICROUSD_PER_1K", "10")
    result, payload = judge_report(tmp_path, "--judge-cost-budget-microusd", "55")
    # 10 micro-USD a call: five calls fit, the sixth is charged and refused.
    assert result.exit_code == 1 and "BUDGET_EXCEEDED" in result.output
    assert payload["stopped"]["reason_code"] == "BUDGET_EXCEEDED"
    assert payload["model_calls"]["calls"] == 5 and payload["model_calls"]["cost_microusd"] == 50
    assert len(stub_judge.requests) == 6
    assert payload["trials_completed"] == 0 and "agreement" not in payload


def test_an_endpoint_error_is_reported_with_its_reason(tmp_path: Path, stub_judge: Any) -> None:
    stub_judge.status = 503
    result, payload = judge_report(tmp_path)
    assert result.exit_code == 1 and "MODEL_PROVIDER_UNAVAILABLE" in result.output
    assert payload["stopped"]["reason_code"] == "MODEL_PROVIDER_UNAVAILABLE"


def test_zero_trials_is_refused(tmp_path: Path, stub_judge: Any) -> None:
    result, _ = judge_report(tmp_path, "--trials", "0")
    assert result.exit_code == 1 and "at least one trial" in result.output


GuardFactory = Callable[[str], ModelPlaneGuard]


@pytest.fixture
def guard_for() -> GuardFactory:
    key = Ed25519PrivateKey.generate()
    config = JudgeRunConfig(
        endpoint="http://127.0.0.1:11434/v1",
        profile="ollama",
        settings=agent_cli.ModelSettings(),
    )

    def make(origin: str) -> ModelPlaneGuard:
        manifest = supportlab_agent_manifest(
            key, model_endpoint=origin, judge=True, judge_pin=judge_pin(config)
        )
        return ModelPlaneGuard(manifest, ManifestVerifier({KEY_ID: key.public_key()}))

    return make


async def test_the_guard_refuses_an_unsigned_origin(guard_for: GuardFactory) -> None:
    guard = guard_for("http://127.0.0.1:11434")
    with pytest.raises(ModelEndpointDenied):
        await guard(
            TargetObservation(
                url="http://127.0.0.1:9999/v1",
                resolved_addresses=(ip_address("127.0.0.1"),),
                hop_index=0,
                kind="model",
            )
        )
    assert guard.decisions[-1]["reason_code"] == "MODEL_ENDPOINT_NOT_SIGNED"


async def test_the_guard_refuses_a_model_endpoint_that_is_a_target(
    guard_for: GuardFactory,
) -> None:
    """A model origin that resolves onto the signed fixture port is a rebind, not a model."""
    guard = guard_for("http://127.0.0.1:28080")
    with pytest.raises(ModelEndpointRebound):
        await guard(
            TargetObservation(
                url="http://127.0.0.1:28080",
                resolved_addresses=(ip_address("127.0.0.1"),),
                hop_index=0,
                kind="model",
            )
        )
    assert guard.decisions[-1]["decision"] == "deny"


def test_trial_zero_keeps_the_pin_and_an_unseeded_pin_is_never_reseeded() -> None:
    config = JudgeRunConfig(endpoint="x", profile="ollama", settings=agent_cli.ModelSettings())
    pin = judge_pin(config)
    assert trial_pin(pin, 0) is pin and trial_pin(pin, 2).decoding.seed == 44
    unseeded = judge_pin(
        JudgeRunConfig(
            endpoint="x", profile="ollama", settings=agent_cli.ModelSettings(seed="none")
        )
    )
    assert trial_pin(unseeded, 3) is unseeded


def test_the_scripted_report_is_unchanged(tmp_path: Path) -> None:
    out = tmp_path / "scripted"
    result = runner.invoke(app, ["judge-report", "--output-dir", str(out)])
    assert result.exit_code == 0, result.output
    payload = json.loads((out / "evaluator-redteam.json").read_text())
    assert set(payload) == {
        "schema_version",
        "note",
        "hardened",
        "negative_control_without_delimiting",
        "agreement",
    }


def test_an_empty_judge_endpoint_is_refused(tmp_path: Path, stub_judge: Any) -> None:
    """What `make judge-report-networked` passes when PURPLELOOP_JUDGE_ENDPOINT is unset."""
    result = runner.invoke(
        app, ["judge-report", "--judge-endpoint", "", "--output-dir", str(tmp_path / "e")]
    )
    assert result.exit_code == 1 and "MODEL_CONFIG_INVALID" in result.output
    assert not stub_judge.requests


def test_a_judge_endpoint_left_in_the_environment_does_not_network_the_scripted_report(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, stub_judge: Any
) -> None:
    """`make judge-report` and CI score the stand-in; a stray variable must not change that."""
    monkeypatch.setenv("PURPLELOOP_JUDGE_ENDPOINT", "http://127.0.0.1:11434/v1")
    result = runner.invoke(app, ["judge-report", "--output-dir", str(tmp_path / "s")])
    assert result.exit_code == 0, result.output
    assert not stub_judge.requests
    assert "scripted judge stand-in" in (tmp_path / "s" / "evaluator-redteam.json").read_text()
