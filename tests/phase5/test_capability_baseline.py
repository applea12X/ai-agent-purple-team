"""The committed approved baseline (WP5.1): what it is, what signed it, and what it is not."""

from __future__ import annotations

import json

import pytest

from purpleloop.control.capabilities import capability_delta
from purpleloop.control.phase5_signing import SignedDocumentError, verify_record_signature
from purpleloop.reporting.gates import GateInputError, budget_gate, risk_class_gate, scope_gate
from purpleloop.runtime import governance
from purpleloop.runtime.demo import ROOT
from purpleloop.schemas.authorization import BudgetLimits


def test_the_committed_baseline_verifies_and_is_the_v1_surface() -> None:
    baseline, keys = governance.committed_baseline()
    verify_record_signature(baseline, keys)
    assert baseline.surface == governance.v1_capability_surface()
    for manifest in governance.v1_lane_manifests():
        assert capability_delta(baseline.surface, manifest) == frozenset()


def test_the_committed_baseline_says_its_key_was_ephemeral() -> None:
    baseline, _ = governance.committed_baseline()
    assert baseline.key_provenance == "ephemeral"
    assert baseline.key_id == governance.BASELINE_KEY_ID
    assert "single author" in baseline.approver
    assert len(baseline.derived_from) == 4


def test_no_private_key_is_committed_beside_it() -> None:
    for path in (ROOT / "baselines").iterdir():
        assert "PRIVATE KEY" not in path.read_text(encoding="utf-8", errors="ignore"), path


def test_an_edited_committed_baseline_fails_its_signature() -> None:
    baseline, keys = governance.committed_baseline()
    widened = baseline.surface.model_copy(update={"proposal_source": "model-driven"})
    with pytest.raises(SignedDocumentError) as edited:
        verify_record_signature(baseline.model_copy(update={"surface": widened}), keys)
    assert edited.value.reason_code == "INVALID_SIGNATURE"


def test_the_v1_surface_has_no_phase5_increase() -> None:
    surface = governance.v1_capability_surface()
    assert {c.value for c in surface.action_classes} == {"read", "write"}
    assert surface.proposal_source == "bounded-search"
    assert surface.model_assets == frozenset({governance.V1_LOCAL_MODEL_ORIGIN})
    assert surface.max_attacker_proposals == 8 and surface.max_attacker_depth == 3


def test_governance_documents_are_not_gate_inputs() -> None:
    """Approvals, baselines, and shadow reports carry no verdict; no gate reads them."""
    baseline, _ = governance.committed_baseline()
    raw = json.loads((ROOT / "baselines" / "corpus-baseline.json").read_text())
    from purpleloop.schemas.phase4 import RiskClassBaseline

    corpus = RiskClassBaseline.model_validate(raw)
    for document in (baseline, baseline.surface):
        with pytest.raises(GateInputError):
            scope_gate([document])  # type: ignore[list-item]
        with pytest.raises(GateInputError):
            risk_class_gate(corpus, [document])  # type: ignore[list-item]
        with pytest.raises(GateInputError):
            budget_gate([], BudgetLimits(requests=1, records=1), [document])  # type: ignore[list-item]
