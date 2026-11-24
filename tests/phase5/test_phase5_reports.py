"""ShadowReport, EvaluationMatrix, MatrixCell, and DefenseDependence validation.

Each reported figure is validated against the counts it summarizes, so each has a test that
fails when the figure is faked: a rejection rate that is not rejected / total, a cell value that
is not successes / n, a classification that does not follow from the credited rows.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pytest
from pydantic import ValidationError

from purpleloop.reporting.phase5_references import (
    reference_defense_dependence,
    reference_matrix,
    reference_matrix_cell,
)
from purpleloop.schemas.phase3 import DecodingParameters, ModelPin
from purpleloop.schemas.phase5 import (
    DefenseDependence,
    EvaluationMatrix,
    MatrixCell,
    MatrixRow,
    ShadowReport,
    classify_dependence,
)

MakeReport = Callable[..., ShadowReport]


# --- shadow report ----------------------------------------------------------------------------


def test_a_shadow_report_round_trips_with_a_stable_digest(make_shadow_report: MakeReport) -> None:
    report = make_shadow_report()
    reloaded = ShadowReport.model_validate_json(report.model_dump_json())
    assert reloaded.report_digest() == report.report_digest()
    assert report.adapter_calls == 0
    assert make_shadow_report(unreachable_steps=2).report_digest() != report.report_digest()


def test_a_shadow_report_that_reached_an_adapter_cannot_exist(
    make_shadow_report: MakeReport,
) -> None:
    with pytest.raises(ValidationError):
        make_shadow_report(adapter_calls=1)


def test_a_faked_rejection_rate_is_refused(make_shadow_report: MakeReport) -> None:
    with pytest.raises(ValidationError, match="rejected / total"):
        make_shadow_report(proposal_rejection_rate=0.0)
    with pytest.raises(ValidationError, match="cannot exceed"):
        make_shadow_report(proposals_rejected=5, proposal_rejection_rate=1.0)
    assert make_shadow_report(
        proposals_total=0, proposals_rejected=0, proposal_rejection_rate=0.0
    ).proposal_rejection_rate == pytest.approx(0.0)
    with pytest.raises(ValidationError, match="rejected / total"):
        make_shadow_report(proposals_total=0, proposals_rejected=0, proposal_rejection_rate=0.5)


def test_shadow_counts_are_positive_and_keyed_by_identifier(
    make_shadow_report: MakeReport,
) -> None:
    with pytest.raises(ValidationError, match="must be positive"):
        make_shadow_report(denials_by_reason={"OPERATION_NOT_ALLOWED": 0})
    with pytest.raises(ValidationError, match="canonical identifier"):
        make_shadow_report(operations_proposed={"not an id": 1})
    with pytest.raises(ValidationError):
        make_shadow_report(action_classes_reached=frozenset({"teleport"}))
    with pytest.raises(ValidationError):
        make_shadow_report(manifest_digest="z" * 64)


# --- evaluation matrix ------------------------------------------------------------------------


def pin(provider: str = "offline", temperature: float = 0.0) -> ModelPin:
    return ModelPin(
        pin_id=f"pin-{provider}",
        provider=provider,  # type: ignore[arg-type]
        model_id="m",
        decoding=DecodingParameters(temperature=temperature, seed=1),
        system_prompt_hash="0" * 64,
    )


def matrix(**overrides: Any) -> EvaluationMatrix:
    data = reference_matrix().model_dump(mode="python")
    data.update(overrides)
    return EvaluationMatrix.model_validate(data)


def real_row(**overrides: Any) -> MatrixRow:
    fields: dict[str, Any] = {
        "row_id": "qwen-sampled",
        "kind": "real-pin",
        "pin": pin("ollama", 0.7),
        "seeds": (11, 12, 13, 14, 15),
        "decoding_label": "sampled",
    }
    fields.update(overrides)
    return MatrixRow.model_validate(fields)


def test_a_matrix_spec_round_trips_and_registers_its_contrasts() -> None:
    blind = reference_matrix().rows[0]
    spec = matrix(rows=(blind, real_row()), defense_columns=("no-defense", "a", "b"))
    assert EvaluationMatrix.model_validate_json(spec.model_dump_json()) == spec
    assert spec.registered_contrasts() == (
        ("reference-blind", "a"),
        ("reference-blind", "b"),
        ("qwen-sampled", "a"),
        ("qwen-sampled", "b"),
    )
    assert spec.contrast_test == "mcnemar-exact" and spec.correction == "holm"


def test_matrix_spec_validation() -> None:
    blind = reference_matrix().rows[0]
    with pytest.raises(ValidationError, match="one seed per repetition"):
        matrix(repetitions=6)
    with pytest.raises(ValidationError):
        matrix(repetitions=4, rows=(blind.model_copy(update={"seeds": (1, 2, 3, 4)}),))
    with pytest.raises(ValidationError, match="baseline column"):
        matrix(baseline_column="missing")
    with pytest.raises(ValidationError, match="unique"):
        matrix(defense_columns=("no-defense", "no-defense"))
    with pytest.raises(ValidationError, match="delimitation-blind"):
        matrix(rows=(real_row(),))
    with pytest.raises(ValidationError, match="row ids must be unique"):
        matrix(rows=(blind, blind))
    with pytest.raises(ValidationError):
        matrix(alpha=0.0)
    with pytest.raises(ValidationError):
        matrix(contrast_test="t-test")


def test_matrix_rows_label_their_decoding_and_kind_honestly() -> None:
    with pytest.raises(ValidationError, match="decoding label"):
        real_row(decoding_label="greedy")
    with pytest.raises(ValidationError, match="decoding label"):
        real_row(pin=pin("ollama", 0.0))
    assert real_row(pin=pin("ollama", 0.0), decoding_label="greedy")
    with pytest.raises(ValidationError, match="real model provider"):
        real_row(pin=pin("offline", 0.7))
    with pytest.raises(ValidationError, match="names its anchor"):
        real_row(anchor="hostile")
    with pytest.raises(ValidationError, match="offline provider"):
        real_row(kind="deterministic-anchor", anchor="hostile")
    with pytest.raises(ValidationError, match="distinct"):
        real_row(seeds=(1, 1, 2, 3, 4))


# --- matrix cell ------------------------------------------------------------------------------


def cell(**overrides: Any) -> MatrixCell:
    data = reference_matrix_cell().model_dump(mode="python")
    data.update(overrides)
    return MatrixCell.model_validate(data)


def test_a_matrix_cell_is_never_binding() -> None:
    assert reference_matrix_cell().provenance == "pinned-stochastic"
    assert cell(provenance="advisory").provenance == "advisory"
    with pytest.raises(ValidationError):
        cell(provenance="deterministic")


def test_a_faked_cell_value_is_refused() -> None:
    with pytest.raises(ValidationError, match="successes / n"):
        cell(value=0.0)
    with pytest.raises(ValidationError, match="inside its interval"):
        cell(ci_low=0.3)
    with pytest.raises(ValidationError, match="cannot exceed"):
        cell(successes=6, value=1.0, ci_high=1.0)
    with pytest.raises(ValidationError):
        cell(n=0)
    reloaded = MatrixCell.model_validate_json(reference_matrix_cell().model_dump_json())
    assert reloaded == reference_matrix_cell()


# --- defense dependence -----------------------------------------------------------------------


def dependence(**overrides: Any) -> DefenseDependence:
    data = reference_defense_dependence().model_dump(mode="python")
    data.update(overrides)
    return DefenseDependence.model_validate(data)


def test_classification_follows_from_the_credited_rows() -> None:
    assert classify_dependence(frozenset({"a", "b"}), frozenset()) == "model-independent"
    assert classify_dependence(frozenset({"a"}), frozenset({"b"})) == "model-dependent"
    assert classify_dependence(frozenset(), frozenset({"a", "b"})) == "ineffective"
    with pytest.raises(ValueError, match="at least one evaluated row"):
        classify_dependence(frozenset(), frozenset())


def test_a_faked_classification_is_refused() -> None:
    with pytest.raises(ValidationError, match="does not follow"):
        dependence(classification="model-dependent")
    mixed = dependence(
        classification="model-dependent",
        credited_rows=frozenset({"qwen-sampled"}),
        uncredited_rows=frozenset({"reference-blind"}),
        trials=10,
    )
    assert mixed.classification == "model-dependent"
    with pytest.raises(ValidationError, match="does not follow"):
        dependence(
            classification="model-independent",
            credited_rows=frozenset({"qwen-sampled"}),
            uncredited_rows=frozenset({"reference-blind"}),
            trials=10,
        )


def test_dependence_requires_the_delimitation_blind_row_and_real_counts() -> None:
    with pytest.raises(ValidationError, match="delimitation-blind row"):
        dependence(delimitation_blind_row="not-evaluated")
    with pytest.raises(ValidationError, match="both credit"):
        dependence(
            credited_rows=frozenset({"reference-blind"}),
            uncredited_rows=frozenset({"reference-blind"}),
        )
    with pytest.raises(ValidationError, match="at least one trial"):
        dependence(credited_rows=frozenset({"reference-blind", "qwen-sampled"}), trials=1)
    with pytest.raises(ValidationError):
        dependence(provenance="deterministic")
    with pytest.raises(ValidationError):
        dependence(enforcement="vibes")
