"""The scope and budget gates compare events within one ledger only (found by the incident drill).

A suite bundle's events are whole ledgers concatenated, and the same control-plane action has
the same digest in every run. Before the fix, ``scope_gate`` matched a permit in one run to an
execution in another, so a run that executed an action its own kernel never permitted passed
whenever any other run of the suite had permitted it (``docs/phase5/drill-acceptance.md``). The
budget gate had the mirror defect: one run's budget denial flagged another run's execution.
"""

from __future__ import annotations

from datetime import UTC, datetime

from purpleloop.reporting.gates import budget_gate, ledger_segments, scope_gate
from purpleloop.runtime.demo import ROOT
from purpleloop.runtime.ledger import EvidenceLedger
from purpleloop.schemas.authorization import BudgetLimits
from purpleloop.schemas.event import EventKind, EvidenceEvent

SAMPLE = ROOT / "docs" / "samples" / "passing-run" / "evidence.jsonl"
X = "c" * 64


def _event(sequence: int, kind: EventKind, decision: str, run: str) -> EvidenceEvent:
    return EvidenceEvent(
        run_id=run,
        trace_id=run,
        sequence=sequence,
        timestamp=datetime(2026, 1, 1, tzinfo=UTC),
        actor="safety-kernel",
        kind=kind,
        manifest_digest=X,
        policy_digest=X,
        action_digest=X,
        decision=decision,
        reason_code="TEST",
    )


def test_a_real_run_cannot_borrow_another_runs_permit() -> None:
    first = EvidenceLedger(SAMPLE).verify()
    executed = next(e for e in first if e.kind == EventKind.RESULT and e.decision == "permit")
    # A second run of the same suite: its ledger starts again at 0, and at its own sequence 3
    # executes the action the first run permitted, with no permit of its own.
    second = [
        *[e.model_copy(update={"run_id": "second"}) for e in first[:3]],
        executed.model_copy(update={"run_id": "second", "sequence": 3}),
    ]
    assert not scope_gate(first).blocked
    decision = scope_gate([*first, *second])
    assert decision.blocked and decision.reason_code == "SCOPE_BYPASS"
    assert decision.detail == "second seq 3: executed without a policy permit"


def test_a_standing_denial_in_another_run_is_not_this_runs_denial() -> None:
    events = [
        _event(0, EventKind.POLICY, "permit", "a"),
        _event(1, EventKind.POLICY, "deny", "a"),
        _event(0, EventKind.POLICY, "permit", "b"),
        _event(2, EventKind.RESULT, "permit", "b"),
    ]
    assert not scope_gate(events).blocked
    within = [*events[:2], _event(2, EventKind.RESULT, "permit", "a")]
    assert scope_gate(within).blocked


def test_a_budget_denial_in_another_run_does_not_flag_this_runs_execution() -> None:
    limits = BudgetLimits(requests=10, records=10)
    events = [
        _event(0, EventKind.POLICY, "permit", "a"),
        _event(1, EventKind.BUDGET, "deny", "a"),
        _event(0, EventKind.POLICY, "permit", "b"),
        _event(2, EventKind.RESULT, "permit", "b"),
    ]
    assert not budget_gate(events, limits, []).blocked
    within = [*events[:2], _event(2, EventKind.RESULT, "permit", "a")]
    decision = budget_gate(within, limits, [])
    assert decision.blocked and decision.detail == "a seq 2: executed after a budget denial"


def test_segments_start_where_a_sequence_stops_increasing() -> None:
    events = [_event(n, EventKind.POLICY, "permit", "r") for n in (0, 1, 2, 0, 1, 0)]
    assert [ledger for ledger, _ in ledger_segments(events)] == [0, 0, 0, 1, 1, 2]
