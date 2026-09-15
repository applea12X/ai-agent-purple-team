"""WP3.6 -- four separate numbers, repetitions, and figures that carry their own caveats."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from purpleloop.control.manifest import ManifestVerifier
from purpleloop.runtime.repetitions import apply_reproducibility, run_repetitions
from purpleloop.runtime.runner import PurpleTeamRunner
from purpleloop.runtime.supportlab import (
    KEY_ID,
    InProcessSupportlab,
    actor_credentials,
    build_agent_runner,
)
from purpleloop.schemas.authorization import AuthorizationManifest
from purpleloop.schemas.phase1 import Phase1Scenario
from purpleloop.schemas.phase3 import (
    DecodingParameters,
    ModelPin,
    RepetitionRecord,
    RepetitionSet,
)
from purpleloop.scoring.phase3 import (
    estimate_tokens,
    mean_interval,
    reproducibility_basis,
    stochastic_report,
    token_accounting,
    wilson_interval,
)

Make = Callable[..., tuple[PurpleTeamRunner, InProcessSupportlab, Path]]


def record(
    index: int, *, security: str, utility: str = "true", under: str = "true", side: int = 1
) -> RepetitionRecord:
    return RepetitionRecord(
        repetition_index=index,
        run_id=f"r-{index}",
        status="passed",
        security_verdict=security,  # type: ignore[arg-type]
        utility_verdict=utility,  # type: ignore[arg-type]
        utility_under_attack_verdict=under,  # type: ignore[arg-type]
        unauthorized_side_effects=side,
        model_pin_id="pin-a",
    )


def repetition_set(records: list[RepetitionRecord], requested: int | None = None) -> RepetitionSet:
    return RepetitionSet(
        scenario_id="s",
        requested=requested if requested is not None else len(records),
        records=tuple(records),
        model_pin_id="pin-a",
    )


# --- the four numbers -------------------------------------------------------------------------


def test_the_four_numbers_are_reported_separately() -> None:
    """A composite would hide the case this corpus exists to show."""
    records = [
        record(0, security="true", utility="true", under="false", side=2),
        record(1, security="true", utility="true", under="false", side=1),
        record(2, security="false", utility="true", under="true", side=0),
    ]
    report = stochastic_report(repetition_set(records))
    assert report.clean_utility.value == 1.0
    assert report.utility_under_attack.value == pytest.approx(1 / 3)
    assert report.attack_success.value == pytest.approx(2 / 3)
    assert report.executed_unauthorized_side_effects.value == pytest.approx(1.0)
    # Four distinct values from the same runs: no single number could carry all of them.
    assert (
        len(
            {
                report.clean_utility.value,
                report.utility_under_attack.value,
                report.attack_success.value,
            }
        )
        == 3
    )


def test_every_stochastic_figure_carries_its_n_seed_policy_and_pin() -> None:
    report = stochastic_report(repetition_set([record(i, security="true") for i in range(5)]))
    for figure in (
        report.clean_utility,
        report.utility_under_attack,
        report.attack_success,
        report.executed_unauthorized_side_effects,
    ):
        assert figure.n == 5
        assert figure.seed_policy == "fixed-per-repetition"
        assert figure.model_pin_id == "pin-a"
        assert figure.provenance == "pinned-stochastic"
        assert figure.ci_low <= figure.value <= figure.ci_high


def test_a_single_deterministic_repetition_stays_deterministic() -> None:
    single = RepetitionSet(
        scenario_id="s",
        requested=1,
        records=(record(0, security="true").model_copy(update={"provenance": "deterministic"}),),
    )
    report = stochastic_report(single)
    assert report.attack_success.provenance == "deterministic"
    assert report.attack_success.n == 1
    assert not report.reproducible
    assert "single paired run" in reproducibility_basis(report)


def test_an_excluded_repetition_reduces_n_and_is_reported() -> None:
    """A repetition that did not complete never quietly leaves the denominator."""
    partial = repetition_set([record(0, security="true"), record(1, security="true")], requested=5)
    report = stochastic_report(partial)
    assert report.attack_success.n == 2
    assert report.attack_success.excluded == 3
    assert report.repetitions.excluded == 3


def test_reproducibility_is_answered_from_the_repetition_set() -> None:
    agreeing = stochastic_report(repetition_set([record(i, security="true") for i in range(5)]))
    assert agreeing.reproducible
    assert "5 repetitions agreed" in reproducibility_basis(agreeing)
    disagreeing = stochastic_report(
        repetition_set([record(0, security="true"), record(1, security="false")])
    )
    assert not disagreeing.reproducible
    assert "disagreed" in reproducibility_basis(disagreeing)


# --- intervals ---------------------------------------------------------------------------------


def test_wilson_interval_widens_as_n_falls() -> None:
    wide = wilson_interval(1, 2)
    narrow = wilson_interval(50, 100)
    assert (wide[1] - wide[0]) > (narrow[1] - narrow[0])
    assert wilson_interval(0, 0) == (0.0, 1.0)
    low, high = wilson_interval(5, 5)
    assert low > 0.5 and high == 1.0


def test_mean_interval_is_deterministic() -> None:
    values = [0.0, 1.0, 2.0, 3.0, 4.0]
    assert mean_interval(values) == mean_interval(values)
    assert mean_interval([2.0]) == (2.0, 2.0)
    assert mean_interval([]) == (0.0, 0.0)


# --- token and cost accounting -------------------------------------------------------------------


def test_token_and_cost_estimates_are_reported_against_actual() -> None:
    pin = ModelPin(
        pin_id="p",
        provider="vllm",
        model_id="m",
        decoding=DecodingParameters(max_output_tokens=100),
        system_prompt_hash="a" * 64,
        price_input_microusd_per_1k=3000,
        price_output_microusd_per_1k=15000,
    )
    tokens, cost = estimate_tokens(pin, model_calls=2, prompt_chars=400)
    assert tokens == 2 * 100 + 2 * 100
    assert cost > 0
    accounting = token_accounting(
        estimated_tokens=tokens, actual_tokens=tokens, estimated_cost=cost, actual_cost=cost
    )
    assert accounting.delta_percent == {"tokens": 0.0, "cost_microusd": 0.0}
    assert all(accounting.within_tolerance.values())


def test_a_cost_overrun_is_reported_as_out_of_tolerance() -> None:
    accounting = token_accounting(
        estimated_tokens=100, actual_tokens=200, estimated_cost=100, actual_cost=105
    )
    assert accounting.delta_percent["tokens"] == 100.0
    assert accounting.within_tolerance["tokens"] is False
    assert accounting.within_tolerance["cost_microusd"] is True


# --- end to end -----------------------------------------------------------------------------------


async def test_repetitions_over_a_real_scenario_answer_reproducibility(
    tmp_path: Path,
    agent_scenarios: list[Phase1Scenario],
    agent_manifest: AuthorizationManifest,
    signing_key: Ed25519PrivateKey,
) -> None:
    scenario = next(s for s in agent_scenarios if s.scenario_id == "agent-indirect-ticket")

    def factory(index: int) -> tuple[PurpleTeamRunner, Path]:
        tokens = actor_credentials()
        control = "SUPPORTLAB-CONTROL-SECRET"
        directory = tmp_path / f"rep-{index}"
        runner = build_agent_runner(
            directory,
            agent_manifest,
            ManifestVerifier({KEY_ID: signing_key.public_key()}),
            actor_tokens=tokens,
            control=control,
            fixture=InProcessSupportlab(tokens, control),
        )
        return runner, directory

    report, summaries = await run_repetitions(
        scenario, agent_manifest, factory, repetitions=5, run_id="rep"
    )
    assert report.repetitions.completed == 5
    assert report.repetitions.exclusion_reasons == ()
    assert report.attack_success.value == 1.0
    assert report.clean_utility.value == 1.0
    # The clean task still works after the attack has landed: a real fourth number, measured.
    assert report.utility_under_attack.n == 5
    assert report.reproducible

    enriched = apply_reproducibility(summaries[0], report)
    assert enriched.findings and enriched.findings[0].reproducible
    assert "5 repetitions agreed" in enriched.findings[0].reproducibility_basis
    assert enriched.stochastic is not None
    # The advisory report never moves the binding status.
    assert enriched.status == summaries[0].status


# --- the report keeps the two kinds apart ---------------------------------------------------


def test_the_html_report_separates_advisory_from_binding(tmp_path: Path) -> None:
    """An advisory number in the same panel as a deterministic one inherits its credibility."""
    from purpleloop.reporting.bundle import advisory_section
    from purpleloop.schemas.phase1 import DetectorResult, LegResult, OracleResult, RunSummary
    from purpleloop.schemas.phase3 import JudgeResult

    def oracle(verdict: str) -> OracleResult:
        return OracleResult(verdict=verdict, oracle_version="state-v1")  # type: ignore[arg-type]

    leg = LegResult(
        seed_hash="a" * 64,
        utility=oracle("true"),
        security=oracle("inconclusive"),
        susceptible=True,
        unauthorized_side_effects=1,
        detectors=(
            DetectorResult(
                rule_id="r", expected=True, observed=True, evidence_ids=("e",), time_to_detect=1
            ),
        ),
        judge=JudgeResult(
            verdict="true",
            rubric_id="exfiltration-v1",
            cited_evidence_ids=("e1",),
            confidence=0.9,
            input_digest="b" * 64,
            model_pin_id="pin-a",
        ),
    )
    report = stochastic_report(repetition_set([record(i, security="true") for i in range(5)]))
    summary = RunSummary(
        run_id="r",
        scenario_id="s",
        status="passed",
        reason="PAIRED_EVALUATION",
        manifest_digest="c" * 64,
        scenario_digest="d" * 64,
        baseline=leg,
        stochastic=report,
    )
    rendered = advisory_section(summary)
    assert "advisory" in rendered and "gates nothing" in rendered
    # Every advisory figure carries its provenance context where a reader will see it.
    assert "pin-a" in rendered and "fixed-per-repetition" in rendered
    assert "Attack success" in rendered and "Utility under attack" in rendered
    assert "exfiltration-v1" in rendered


def test_a_run_with_no_advisory_content_renders_no_advisory_panel() -> None:
    from purpleloop.reporting.bundle import advisory_section
    from purpleloop.schemas.phase1 import RunSummary

    summary = RunSummary(
        run_id="r",
        scenario_id="s",
        status="passed",
        reason="x",
        manifest_digest="c" * 64,
        scenario_digest="d" * 64,
    )
    assert advisory_section(summary) == ""
