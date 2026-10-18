"""The nightly lane's closed outcome vocabulary and the stochastic reproduction number."""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest
from typer.testing import CliRunner

from purpleloop.agent_cli import CREDENTIAL_ENV
from purpleloop.cli import app
from purpleloop.control.budgets import BudgetError
from purpleloop.runtime.demo import ROOT
from purpleloop.schemas.phase3 import RepetitionRecord, RepetitionSet
from purpleloop.scoring.phase4 import classify_stochastic_failure, reproduction_record


class _LaneUnavailable(RuntimeError):
    reason_code = "STOCHASTIC_LANE_UNAVAILABLE"


class _ModelDown(RuntimeError):
    reason_code = "MODEL_PROVIDER_UNAVAILABLE"


@pytest.mark.parametrize(
    ("error", "expected"),
    [
        (_LaneUnavailable("no credential"), "skip-no-credential"),
        (BudgetError("token cap"), "budget-stop"),
        (_ModelDown("upstream 503"), "endpoint-error"),
        (httpx.ConnectError("refused"), "endpoint-error"),
        (TimeoutError("deadline"), "endpoint-error"),
        (RuntimeError("oracle disagreed"), "fail"),
    ],
)
def test_failures_classify_into_the_closed_vocabulary(error: BaseException, expected: str) -> None:
    outcome = classify_stochastic_failure(error, scenario_id="s", model_pin_id="pin")
    assert outcome.outcome == expected
    assert outcome.scenario_id == "s" and outcome.model_pin_id == "pin"
    assert outcome.reason_code


def test_an_endpoint_error_is_never_reported_as_a_scenario_failure() -> None:
    """The distinction WP2.0 drew for image builds, applied to model endpoints."""
    outcome = classify_stochastic_failure(httpx.ReadTimeout("slow provider"))
    assert outcome.outcome == "endpoint-error"
    assert outcome.outcome != "fail"


def record(index: int, verdict: str) -> RepetitionRecord:
    return RepetitionRecord(
        repetition_index=index,
        run_id=f"run-{index}",
        status="passed",
        security_verdict=verdict,  # type: ignore[arg-type]
        utility_verdict="true",
        model_pin_id="pin",
    )


def repetitions(*verdicts: str) -> RepetitionSet:
    return RepetitionSet(
        scenario_id="s",
        requested=len(verdicts),
        records=tuple(record(index, verdict) for index, verdict in enumerate(verdicts)),
        model_pin_id="pin",
    )


def test_reproduction_rate_counts_every_repetition() -> None:
    result = reproduction_record(repetitions("true", "true", "false", "true", "true"))
    assert result.n == 5 and result.matching == 4 and result.rate == 0.8
    assert result.mismatched_repetitions == (2,)
    assert result.gap_reason  # a gap must be explained


def test_full_agreement_needs_no_gap_reason() -> None:
    result = reproduction_record(repetitions("true", "true", "true", "true", "true"))
    assert result.rate == 1.0 and result.gap_reason == ""


def test_no_completed_repetition_is_a_zero_rate_with_a_reason() -> None:
    empty = RepetitionSet(scenario_id="s", requested=5, records=(), model_pin_id="pin")
    result = reproduction_record(empty)
    assert result.n == 0 and result.rate == 0.0
    assert result.gap_reason == "no repetition completed"


def test_a_skipped_lane_surfaces_its_outcome_and_writes_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The skip is classified and printed, and the Phase 3 no-bundle invariant still holds."""
    monkeypatch.delenv(CREDENTIAL_ENV, raising=False)
    result = CliRunner().invoke(
        app,
        [
            "agent-run",
            str(ROOT / "scenarios" / "agent" / "agent-indirect-ticket.yaml"),
            str(tmp_path / "skipped"),
            "--endpoint",
            "https://models.invalid/v1",
        ],
    )
    assert result.exit_code == 0
    assert '"outcome":"skip-no-credential"' in result.output
    assert not (tmp_path / "skipped").exists()


def test_a_completed_run_writes_its_classified_outcome(tmp_path: Path) -> None:
    out = tmp_path / "run"
    result = CliRunner().invoke(
        app,
        [
            "agent-run",
            str(ROOT / "scenarios" / "agent" / "agent-indirect-ticket.yaml"),
            str(out),
            "--repetitions",
            "2",
        ],
    )
    assert result.exit_code == 0, result.output
    outcome = json.loads((out / "outcome.json").read_text())
    assert outcome["outcome"] == "pass"
    reproduction = json.loads((out / "reproduction.json").read_text())
    assert reproduction["n"] == 2 and reproduction["rate"] == 1.0
