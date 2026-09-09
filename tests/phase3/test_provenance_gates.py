"""WP3.0 -- the verdict-provenance boundary.

These tests exist so that the Phase 3 contract change is enforced by types and assertions rather
than by documentation. They land before any stochastic component does, so a judge or a real model
cannot be wired in without declaring what kind of verdict it produces.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from purpleloop.schemas.phase1 import (
    DetectorResult,
    Finding,
    GroundTruth,
    LegResult,
    OracleResult,
    RunSummary,
)
from purpleloop.schemas.phase3 import (
    BINDING_PROVENANCE,
    AdvisoryVerdictError,
    DecodingParameters,
    JudgeResult,
    Measurement,
    ModelPin,
    is_binding,
    require_binding,
)
from purpleloop.scoring.phase1 import corpus_metrics

DIGEST = "a" * 64


def oracle(verdict: str, provenance: str = BINDING_PROVENANCE) -> OracleResult:
    return OracleResult(
        verdict=verdict,  # type: ignore[arg-type]
        provenance=provenance,  # type: ignore[arg-type]
        oracle_version="state-v1",
        evidence_ids=("evidence-1",),
    )


def judge(verdict: str) -> JudgeResult:
    return JudgeResult(
        verdict=verdict,  # type: ignore[arg-type]
        rubric_id="exfiltration-v1",
        cited_evidence_ids=("evidence-1",),
        confidence=0.99,
        input_digest=DIGEST,
        model_pin_id="judge-pin",
    )


def leg(
    security: str, utility: str = "true", attached_judge: JudgeResult | None = None
) -> LegResult:
    return LegResult(
        seed_hash=DIGEST,
        utility=oracle(utility),
        security=oracle(security),
        susceptible=False,
        unauthorized_side_effects=0,
        detectors=(
            DetectorResult(
                rule_id="r1", expected=True, observed=True, evidence_ids=("e",), time_to_detect=1
            ),
        ),
        judge=attached_judge,
    )


def finding(provenance: str = BINDING_PROVENANCE) -> Finding:
    return Finding(
        provenance=provenance,  # type: ignore[arg-type]
        finding_id="f-1",
        scenario_id="s-1",
        asset_id="supportlab-data",
        attacker_goal="goal",
        observed_impact="impact",
        evidence_ids=("evidence-1",),
        oracle_version="state-v1",
        manifest_digest=DIGEST,
        scenario_digest=DIGEST,
        seed_hash=DIGEST,
        reproducible=False,
        severity_rationale="synthetic",
        taxonomy_mappings={"owasp-llm-2025": ("LLM01",)},
        status="confirmed",
        mitigation="object-ownership",
    )


def summary(baseline: LegResult, replay: LegResult, findings: tuple[Finding, ...]) -> RunSummary:
    return RunSummary(
        run_id="run-1",
        scenario_id="s-1",
        status="passed",
        reason="PAIRED_EVALUATION",
        manifest_digest=DIGEST,
        scenario_digest=DIGEST,
        baseline=baseline,
        replay=replay,
        findings=findings,
    )


GROUND_TRUTH = GroundTruth.model_validate(
    {
        "cases": [
            {
                "scenario_id": "s-1",
                "positive_control": "baseline",
                "expected_findings": 1,
                "negative_control": "defended-replay",
                "expected_negative_findings": 0,
            }
        ]
    }
)


def test_existing_verdicts_are_deterministic_by_default() -> None:
    """Phases 0-2 produced deterministic verdicts; the default says so without restating it."""
    assert oracle("true").provenance == BINDING_PROVENANCE
    assert finding().provenance == BINDING_PROVENANCE
    assert is_binding(oracle("true"))


def test_a_disagreeing_judge_changes_nothing() -> None:
    """The core Phase 3 assertion: an advisory judgement does not move a binding number.

    The deterministic oracle says the defended replay is clean; the judge says it is not. The
    corpus metric is computed both ways and must be identical, because the judge is not an input.
    """
    without = summary(leg("true"), leg("false"), (finding(),))
    with_judge = summary(leg("true"), leg("false", attached_judge=judge("true")), (finding(),))

    assert corpus_metrics(GROUND_TRUTH, [without]) == corpus_metrics(GROUND_TRUTH, [with_judge])
    metrics = corpus_metrics(GROUND_TRUTH, [with_judge])
    assert metrics["seeded_recall"] == 1.0
    assert metrics["false_positives"] == 0
    assert with_judge.replay is not None and with_judge.replay.judge is not None
    assert with_judge.replay.judge.verdict == "true"  # recorded, and ignored by the gate


def test_advisory_finding_is_refused_by_the_corpus_gate() -> None:
    """An advisory result placed in a gate's input path is rejected, never averaged in."""
    advisory = summary(leg("true"), leg("false"), (finding("advisory"),))
    with pytest.raises(AdvisoryVerdictError):
        corpus_metrics(GROUND_TRUTH, [advisory])


def test_advisory_negative_control_is_refused_by_the_corpus_gate() -> None:
    stochastic = summary(leg("true"), leg("false"), (finding(),))
    replay = stochastic.replay
    assert replay is not None
    tainted = stochastic.model_copy(
        update={
            "replay": replay.model_copy(update={"security": oracle("false", "pinned-stochastic")})
        }
    )
    with pytest.raises(AdvisoryVerdictError):
        corpus_metrics(GROUND_TRUTH, [tainted])


def test_require_binding_names_the_offending_type() -> None:
    with pytest.raises(AdvisoryVerdictError) as caught:
        require_binding(oracle("true", "advisory"))
    assert "OracleResult" in str(caught.value)
    assert caught.value.reason_code == "ADVISORY_VERDICT_REJECTED"
    require_binding(None, oracle("true"))  # None and binding values pass


def test_judge_result_cannot_claim_to_be_binding() -> None:
    """A judgement is advisory by construction, not by convention."""
    with pytest.raises(ValidationError):
        JudgeResult(
            provenance="deterministic",
            verdict="true",
            rubric_id="r",
            cited_evidence_ids=("e",),
            input_digest=DIGEST,
            model_pin_id="pin",
        )


def test_judge_abstention_records_its_reason_and_needs_no_citation() -> None:
    abstained = JudgeResult(
        verdict="abstain",
        rubric_id="r",
        abstention_reason="evidence did not resolve the question",
        input_digest=DIGEST,
        model_pin_id="pin",
    )
    assert abstained.verdict == "abstain" and abstained.provenance == "advisory"
    with pytest.raises(ValidationError):
        JudgeResult(verdict="abstain", rubric_id="r", input_digest=DIGEST, model_pin_id="pin")


def test_a_non_abstaining_judgement_must_cite_evidence() -> None:
    with pytest.raises(ValidationError):
        JudgeResult(verdict="true", rubric_id="r", input_digest=DIGEST, model_pin_id="pin")


def test_stochastic_measurement_must_name_its_model_pin() -> None:
    """A figure without its n, seed policy, and model pin does not serialize."""
    with pytest.raises(ValidationError):
        Measurement(
            provenance="pinned-stochastic",
            value=0.6,
            n=5,
            ci_low=0.3,
            ci_high=0.8,
            seed_policy="fixed-per-repetition",
        )
    ok = Measurement(
        provenance="pinned-stochastic",
        value=0.6,
        n=5,
        ci_low=0.3,
        ci_high=0.8,
        seed_policy="fixed-per-repetition",
        model_pin_id="pin-a",
    )
    assert ok.n == 5 and ok.model_pin_id == "pin-a"


def test_measurement_rejects_an_inverted_interval() -> None:
    with pytest.raises(ValidationError):
        Measurement(value=0.5, n=1, ci_low=0.9, ci_high=0.1, seed_policy="fixed")


def test_model_pin_reports_reproducibility_honestly() -> None:
    """A pin without a version or a seed is recorded as such, not treated as reproducible."""
    unpinned = ModelPin(
        pin_id="p", provider="openai-compatible", model_id="m", system_prompt_hash=DIGEST
    )
    assert not unpinned.reproducible
    pinned = ModelPin(
        pin_id="p",
        provider="vllm",
        model_id="m",
        model_version="2026-05-01",
        decoding=DecodingParameters(seed=7),
        system_prompt_hash=DIGEST,
    )
    assert pinned.reproducible


def test_finding_states_why_reproducibility_is_not_asserted() -> None:
    assert "single paired run" in finding().reproducibility_basis
