"""Gate isolation for every Phase 5 output type (plan §2.3, §2.5, §5 "Gate isolation").

Matrix cells and defense-dependence classifications are advisory by type; adjudication records
are human labels and not verdicts at all. Each is constructed here and pushed at every gate
input it could plausibly be smuggled through. Each must be refused with
:class:`GateInputError` (an :class:`AdvisoryVerdictError`) before any decision is computed --
and the clean inputs the gates already accepted must still produce the same decisions.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

import pytest

from purpleloop.reporting.gates import (
    GateInputError,
    _reference_event,
    _reference_summary,
    all_gates,
    budget_gate,
    critical_regression_gate,
    risk_class_gate,
    schema_digests,
    schema_drift_gate,
    scope_gate,
)
from purpleloop.reporting.phase5_references import (
    reference_adjudication,
    reference_defense_dependence,
    reference_matrix_cell,
)
from purpleloop.runtime.demo import ROOT
from purpleloop.schemas.authorization import BudgetLimits
from purpleloop.schemas.phase3 import AdvisoryVerdictError, Scored, require_binding
from purpleloop.schemas.phase4 import (
    RegressionEntry,
    RegressionRegistry,
    RiskClassBaseline,
    RiskClassMetrics,
)
from purpleloop.schemas.phase5 import CONTRACT_VERSIONS

PHASE5_OUTPUTS: dict[str, Callable[[], Any]] = {
    "matrix-cell": reference_matrix_cell,
    "defense-dependence": reference_defense_dependence,
    "adjudication-record": reference_adjudication,
}

LIMITS = BudgetLimits(requests=100, records=100)
REGISTRY = RegressionRegistry(
    entries=(
        RegressionEntry(
            finding_class="reference-finding",
            scenario_id="schema-reference",
            test="tests/t.py::test_a",
            status="covered",
        ),
    )
)
METRICS = RiskClassMetrics(
    risk_class="prompt-injection",
    scenarios=1,
    seeded_true_positives=1,
    seeded_false_negatives=0,
    false_positives=0,
    negative_controls=1,
    defended_unauthorized_side_effects=0,
)
BASELINE = RiskClassBaseline(
    recorded_at=_reference_event().timestamp, corpus="reference", classes=(METRICS,)
)


def clean_inputs(**overrides: Any) -> dict[str, Any]:
    inputs: dict[str, Any] = {
        "events": [_reference_event()],
        "limits": LIMITS,
        "summaries": [_reference_summary()],
        "registry": REGISTRY,
        "outcomes": {"tests/t.py::test_a": True},
        "schema_baseline": schema_digests(),
        "risk_baseline": BASELINE,
        "risk_current": [METRICS],
    }
    inputs.update(overrides)
    return inputs


def test_gate_input_error_is_an_advisory_verdict_error() -> None:
    assert issubclass(GateInputError, AdvisoryVerdictError)


def test_matrix_outputs_are_refused_by_require_binding() -> None:
    for build in (reference_matrix_cell, reference_defense_dependence):
        item = build()
        assert isinstance(item, Scored) and item.provenance != "deterministic"
        with pytest.raises(AdvisoryVerdictError):
            require_binding(item)


def test_an_adjudication_record_is_not_a_verdict_of_any_provenance() -> None:
    record = reference_adjudication()
    assert not isinstance(record, Scored)
    assert not hasattr(record, "provenance")


@pytest.mark.parametrize("kind", sorted(PHASE5_OUTPUTS))
def test_all_gates_refuse_a_phase5_output_as_a_summary(kind: str) -> None:
    smuggled = PHASE5_OUTPUTS[kind]()
    with pytest.raises(GateInputError, match="not a gate input"):
        all_gates(**clean_inputs(summaries=[_reference_summary(), smuggled]))


@pytest.mark.parametrize("kind", sorted(PHASE5_OUTPUTS))
def test_all_gates_refuse_a_phase5_output_as_risk_metrics(kind: str) -> None:
    smuggled = PHASE5_OUTPUTS[kind]()
    with pytest.raises(GateInputError):
        all_gates(**clean_inputs(risk_current=[METRICS, smuggled]))


@pytest.mark.parametrize("kind", sorted(PHASE5_OUTPUTS))
def test_each_gate_refuses_a_phase5_output_at_every_typed_input(kind: str) -> None:
    smuggled = PHASE5_OUTPUTS[kind]()
    with pytest.raises(GateInputError):
        scope_gate([_reference_event(), smuggled])
    with pytest.raises(GateInputError):
        budget_gate([], LIMITS, [smuggled])
    with pytest.raises(GateInputError):
        budget_gate([smuggled], LIMITS, [])
    with pytest.raises(GateInputError):
        budget_gate([], smuggled, [])
    with pytest.raises(GateInputError):
        critical_regression_gate(smuggled, {})
    with pytest.raises(GateInputError):
        critical_regression_gate(REGISTRY, {"tests/t.py::test_a": smuggled})
    with pytest.raises(GateInputError):
        schema_drift_gate({**schema_digests(), "x": smuggled}, schema_digests())
    with pytest.raises(GateInputError):
        risk_class_gate(BASELINE, [smuggled])
    with pytest.raises(GateInputError):
        risk_class_gate(smuggled, [METRICS])


def test_clean_inputs_keep_their_decisions() -> None:
    """The type checks refuse new types only; every existing decision is unchanged."""
    decisions = all_gates(**clean_inputs())
    assert [(d.gate, d.blocked, d.reason_code) for d in decisions] == [
        ("scope-bypass", False, "NO_BYPASS_OBSERVED"),
        ("critical-regression", False, "REGISTRY_TESTS_PASSED"),
        ("schema-drift", False, "CANONICAL_BYTES_STABLE"),
        ("budget-failure", False, "BUDGETS_HELD"),
        ("risk-class-regression", False, "WITHIN_BASELINE"),
    ]
    assert scope_gate([]).reason_code == "NO_EVIDENCE"


# --- the schema-drift gate covers every Phase 5 reference -------------------------------------

PHASE5_REFERENCES = {
    "authorization-manifest-1.5",
    "scenario-1.4",
    "shadow-report-1.0",
    "risk-approval-1.0",
    "evaluation-matrix-1.0",
    "matrix-cell-1.0",
    "defense-dependence-1.0",
    "adjudication-record-1.0",
}


def test_every_phase5_contract_has_a_committed_reference_digest() -> None:
    committed = json.loads((ROOT / "baselines" / "schema-digests.json").read_text())["digests"]
    assert PHASE5_REFERENCES <= committed.keys()
    assert {f"{name}-{version.rsplit('.', 1)[0]}" for name, version in CONTRACT_VERSIONS} == (
        PHASE5_REFERENCES
    )
    decision = schema_drift_gate(committed, schema_digests())
    assert not decision.blocked, decision.detail


@pytest.mark.parametrize("name", sorted(PHASE5_REFERENCES))
def test_drift_in_a_phase5_reference_blocks(name: str) -> None:
    observed = schema_digests()
    decision = schema_drift_gate({**observed, name: "0" * 64}, observed)
    assert decision.blocked and f"drifted: {name}" in decision.detail
    missing = {key: value for key, value in observed.items() if key != name}
    decision = schema_drift_gate(missing, observed)
    assert decision.blocked and "bump required" in decision.detail
