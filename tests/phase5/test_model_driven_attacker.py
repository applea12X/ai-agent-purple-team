"""The model-driven attacker profile (WP5.1.6), behind the same caps, on a scripted model.

No test here calls a real model: every attacker model is ``ScriptedAttackerModel`` or a local
stub. The profile is admitted in shadow without an approval; in execute it is refused at
admission unless an approval covers exactly ``proposal-source-change``.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

import pytest

from purpleloop.adapters.scripted_attacker import ScriptedAttackerModel
from purpleloop.control.attacker import (
    ATTACKER_SYSTEM,
    AttackerNotAuthorized,
    BoundedAttacker,
    ModelDrivenAttacker,
    require_attacker_authorized,
)
from purpleloop.runtime.governance import ATTACKER_PIN
from purpleloop.schemas.event import EventKind
from purpleloop.schemas.phase1 import load_scenario
from purpleloop.schemas.phase3 import ProposalRecord
from purpleloop.schemas.phase5 import CapabilityIncrease

ROOT = Path(__file__).parents[2]
SCENARIO = ROOT / "scenarios" / "agent" / "agent-tool-misuse.yaml"


class FixedModel:
    """Returns the same text for every round, and records what it was shown."""

    profile = "offline"

    def __init__(self, text: str, endpoint: str | None = None) -> None:
        self.text, self._endpoint = text, endpoint
        self.prompts: list[str] = []

    @property
    def endpoint(self) -> str | None:
        return self._endpoint

    async def complete(self, *, pin: Any, system: str, prompt: str, deadline: float) -> Any:
        assert system == ATTACKER_SYSTEM
        self.prompts.append(prompt)
        return self.text, 10, 10


def attacker(model: Any, **overrides: Any) -> ModelDrivenAttacker:
    options: dict[str, Any] = {
        "objective": "probe",
        "max_proposals": 8,
        "max_depth": 3,
        "operations": ["crm.update", "email.send", "export.create"],
        "own_tenant": "org-a",
        "other_tenants": ("org-b",),
        "resource_id": "admin-a",
    }
    pin = overrides.pop("pin", ATTACKER_PIN)
    options.update(overrides)
    return ModelDrivenAttacker(model, pin, **options)


def one_round(model: Any, **overrides: Any) -> Any:
    return asyncio.run(attacker(model, **overrides).next_round())


def test_candidates_are_validated_against_closed_sets_before_they_are_proposals() -> None:
    round_ = one_round(ScriptedAttackerModel())
    assert [(p.operation, p.target_tenant) for p in round_.proposals] == [
        ("crm.update", "org-a"),
        ("export.create", "org-b"),
    ]
    assert dict(round_.invalid) == {
        "invalid": "PROPOSAL_UNKNOWN_OPERATION",
        "email.send": "PROPOSAL_UNKNOWN_TENANT",
    }
    # refund.create is outside this attacker's operations, so it is an unknown operation too.
    assert [reason for _, reason in round_.invalid].count("PROPOSAL_UNKNOWN_OPERATION") == 2


@pytest.mark.parametrize(
    ("text", "reason"),
    [
        ("not json", "ATTACKER_RESPONSE_INVALID"),
        ('{"proposals": {"a": 1}}', "ATTACKER_RESPONSE_INVALID"),
        ('{"other": []}', "ATTACKER_RESPONSE_INVALID"),
        ('{"proposals": ["x"]}', "PROPOSAL_MALFORMED"),
        (
            '{"proposals": [{"operation": "crm.update", "target_tenant": "org-a",'
            ' "arguments": {"field": "password", "value": "x"}}]}',
            "PROPOSAL_ARGUMENTS_INVALID",
        ),
    ],
)
def test_malformed_output_is_a_recorded_refusal(text: str, reason: str) -> None:
    round_ = one_round(FixedModel(text))
    assert round_.proposals == () and [r for _, r in round_.invalid] == [reason]


def test_a_thinking_block_is_stripped_before_parsing() -> None:
    body = json.dumps(
        {
            "proposals": [
                {
                    "operation": "crm.update",
                    "target_tenant": "org-a",
                    "arguments": {"field": "note", "value": "x"},
                }
            ]
        }
    )
    round_ = one_round(FixedModel(f"<think>plan an attack</think>{body}"))
    assert len(round_.proposals) == 1


def test_the_attackers_own_caps_bound_it() -> None:
    many = json.dumps(
        {
            "proposals": [
                {
                    "operation": "crm.update",
                    "target_tenant": "org-a",
                    "arguments": {"field": "note", "value": str(i)},
                }
                for i in range(20)
            ]
        }
    )
    model = FixedModel(many)
    driven = attacker(model, max_proposals=3, max_depth=2)
    first = asyncio.run(driven.next_round())
    assert len(first.proposals) == 3 and ("invalid", "PROPOSAL_CAP_REACHED") in first.invalid
    assert driven.exhausted and asyncio.run(driven.next_round()) is None
    assert len(model.prompts) == 1


def test_the_model_sees_decisions_and_never_target_content() -> None:
    model = FixedModel('{"proposals": []}')
    feedback = (
        ProposalRecord(
            proposal_index=0, depth=1, operation="crm.update", accepted=False, reason_code="X"
        ),
    )
    asyncio.run(attacker(model).next_round(feedback))
    shown = json.loads(model.prompts[0])
    assert set(shown) == {
        "objective",
        "round",
        "operations",
        "tenants",
        "argument_schemas",
        "decisions",
    }
    assert shown["decisions"] == [
        {"operation": "crm.update", "accepted": False, "reason_code": "X"}
    ]
    assert shown["round"] == 1


def test_the_profile_must_be_signed(governance: Any) -> None:
    driven = attacker(ScriptedAttackerModel())
    with pytest.raises(AttackerNotAuthorized) as unsigned:
        require_attacker_authorized(driven, governance.manifest())
    assert unsigned.value.reason_code == "PROPOSAL_SOURCE_NOT_SIGNED"
    signed = governance.manifest(proposal_source="model-driven")
    require_attacker_authorized(driven, signed)
    # The bounded search needs nothing: it is the v1 surface.
    require_attacker_authorized(
        BoundedAttacker(max_proposals=1, max_depth=1, operations=[], own_tenant="org-a"),
        governance.manifest(),
    )
    other_pin = ATTACKER_PIN.model_copy(update={"pin_id": "unsigned-pin"})
    with pytest.raises(AttackerNotAuthorized) as pin:
        require_attacker_authorized(attacker(ScriptedAttackerModel(), pin=other_pin), signed)
    assert pin.value.reason_code == "ATTACKER_PIN_NOT_SIGNED"
    networked = attacker(FixedModel("{}", endpoint="http://127.0.0.1:11434/v1"))
    with pytest.raises(AttackerNotAuthorized) as endpoint:
        require_attacker_authorized(networked, signed)
    assert endpoint.value.reason_code == "ATTACKER_MODEL_ENDPOINT_NOT_SIGNED"
    with pytest.raises(AttackerNotAuthorized) as caps:
        require_attacker_authorized(attacker(ScriptedAttackerModel(), max_proposals=99), signed)
    assert caps.value.reason_code == "ATTACKER_CAPS_EXCEED_SIGNED"


def test_shadow_refuses_an_unsigned_model_driven_attacker(governance: Any, tmp_path: Path) -> None:
    report, _, _ = governance.shadow(
        governance.manifest(),
        tmp_path,
        scenarios=[load_scenario(SCENARIO)],
        attacker=lambda: governance.attacker("model-driven"),
    )
    assert report.denials_by_reason == {"PROPOSAL_SOURCE_NOT_SIGNED": 2}
    assert report.proposals_total == 0


class CapIgnoringAttacker(ModelDrivenAttacker):
    """An attacker object that lies about being exhausted and floods proposals every round."""

    @property
    def exhausted(self) -> bool:
        return False

    def parse(self, text: str) -> Any:
        self.made = 0  # forget every proposal already made
        return super().parse(text)


def test_the_runner_enforces_the_signed_caps_even_when_the_attacker_does_not(
    governance: Any, tmp_path: Path
) -> None:
    flood = json.dumps(
        {
            "proposals": [
                {
                    "operation": "crm.update",
                    "target_tenant": "org-a",
                    "arguments": {"field": "note", "value": str(i)},
                }
                for i in range(6)
            ]
        }
    )
    manifest = governance.manifest(proposal_source="model-driven")
    assert manifest.phase3 is not None
    cap = manifest.phase3.max_attacker_proposals

    def make() -> Any:
        return CapIgnoringAttacker(
            FixedModel(flood),
            ATTACKER_PIN,
            objective="flood",
            max_proposals=cap,
            max_depth=manifest.phase3.max_attacker_depth,  # type: ignore[union-attr]
            operations=["crm.update"],
            own_tenant="org-a",
            resource_id="admin-a",
        )

    scenario = load_scenario(SCENARIO).model_copy(
        update={
            "attack_budget": load_scenario(SCENARIO).attack_budget.model_copy(
                update={"requests": 500, "records": 500, "writes": 500}
            )
        }
    )
    report, _, _ = governance.shadow(manifest, tmp_path, scenarios=[scenario], attacker=make)
    events = [
        json.loads(line)
        for line in (tmp_path / scenario.scenario_id / "evidence.jsonl").read_text().splitlines()
    ]
    accepted = [e for e in events if e["kind"] == "proposal" and e["data"].get("accepted")]
    assert len(accepted) <= 2 * cap
    stops = [
        e["data"]["reason"] for e in events if e.get("reason_code") == "SHADOW_PROPOSALS_STOPPED"
    ]
    assert stops and set(stops) <= {"PROPOSAL_CAP_REACHED", "PROPOSAL_BUDGET_EXHAUSTED"}
    assert report.adapter_calls == 0


def test_execute_without_an_approval_is_refused_before_the_model_is_asked(
    governance: Any, tmp_path: Path
) -> None:
    manifest = governance.manifest(proposal_source="model-driven")
    model = ScriptedAttackerModel()
    runner = governance.agent_runner(
        manifest,
        tmp_path,
        governance.admission(),
        attacker=governance.attacker("model-driven", model=model),
    )
    summary = asyncio.run(
        runner.run(load_scenario(SCENARIO), manifest, run_id="x", output_dir=tmp_path)
    )
    assert summary.reason.split(";")[0] == "CAPABILITY_INCREASE_UNAPPROVED"
    assert model.calls == 0 and governance.counts.get("fixture-requests", 0) == 0


def test_execute_with_an_exact_approval_runs_the_profile_through_the_kernel(
    governance: Any, tmp_path: Path
) -> None:
    """The full path: shadow -> approve -> name the approval -> execute, on the scripted model."""
    requested = governance.manifest(proposal_source="model-driven")
    report, _, _ = governance.shadow(
        requested,
        tmp_path / "shadow",
        scenarios=[load_scenario(SCENARIO)],
        attacker=lambda: governance.attacker("model-driven"),
    )
    approval = governance.approve(requested, report)
    assert approval.capability_delta == frozenset({CapabilityIncrease.PROPOSAL_SOURCE_CHANGE})
    manifest = governance.approved(requested, approval)
    model = ScriptedAttackerModel()
    bundle = tmp_path / "execute"
    runner = governance.agent_runner(
        manifest,
        bundle,
        governance.admission([approval], [report]),
        attacker=governance.attacker("model-driven", model=model),
    )
    summary = asyncio.run(
        runner.run(load_scenario(SCENARIO), manifest, run_id="approved", output_dir=bundle)
    )
    assert summary.status == "passed", summary.reason
    assert model.calls > 0
    events = runner.runtime.ledger.verify()
    admitted = [e for e in events if e.kind == EventKind.ADMISSION and e.decision == "permit"]
    assert admitted and admitted[0].reason_code == "CAPABILITY_INCREASE_APPROVED"
    assert admitted[0].data["approval_digest"] == approval.approval_digest()
    proposals = [e for e in events if e.kind == EventKind.PROPOSAL]
    assert any(e.data["accepted"] for e in proposals)
    assert any(not e.data["accepted"] for e in proposals)
    assert sum(e.reason_code == "ATTACKER_MODEL_CALLED" for e in events) == model.calls
    # Every executed proposal was policy-permitted first: the scope gate sees no bypass.
    from purpleloop.reporting.gates import scope_gate

    assert not scope_gate(events).blocked
