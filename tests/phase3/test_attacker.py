"""WP3.4 -- the bounded adaptive attacker. Proposals are typed, capped, and never widen scope."""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path

from purpleloop.control.attacker import BoundedAttacker
from purpleloop.control.phase3_tools import INTENT_OPERATIONS
from purpleloop.runtime.runner import PurpleTeamRunner
from purpleloop.runtime.supportlab import InProcessSupportlab
from purpleloop.schemas.authorization import AuthorizationManifest
from purpleloop.schemas.phase1 import Phase1Scenario

Make = Callable[..., tuple[PurpleTeamRunner, InProcessSupportlab, Path]]


def attacker(**overrides: object) -> BoundedAttacker:
    fields: dict[str, object] = {
        "max_proposals": 12,
        "max_depth": 3,
        "operations": ["email.send", "crm.update", "export.create"],
        "own_tenant": "org-a",
        "other_tenants": ["org-b"],
        "resource_id": "admin-a",
    }
    fields.update(overrides)
    return BoundedAttacker(**fields)  # type: ignore[arg-type]


def test_proposals_are_deterministic_and_capped() -> None:
    first, second = attacker().proposals(), attacker().proposals()
    assert first == second
    assert len(first) == 12
    assert max(p.depth for p in first) <= 3
    assert len(attacker(max_proposals=3).proposals()) == 3


def test_a_proposal_names_only_a_registered_operation() -> None:
    for proposal in attacker().proposals():
        assert proposal.operation in INTENT_OPERATIONS
        assert BoundedAttacker.adapter_for(proposal.operation) in {"tool", "http"}


def test_an_unregistered_operation_is_dropped_before_it_is_proposed() -> None:
    """The attacker cannot introduce an operation the registry does not declare."""
    built = attacker(operations=["email.send", "shell.exec", "fixture.teardown"])
    assert built.operations == ("email.send",)
    assert all(p.operation == "email.send" for p in built.proposals())


def test_zero_caps_produce_no_proposals() -> None:
    assert attacker(max_proposals=0).proposals() == ()
    assert attacker(max_depth=0).proposals() == ()


async def test_rejected_proposals_are_evidence_not_errors(
    make_agent_runner: Make,
    agent_scenarios: list[Phase1Scenario],
    agent_manifest: AuthorizationManifest,
) -> None:
    """Cross-tenant probes are refused at compile time; the run completes and records each one."""
    scenario = next(s for s in agent_scenarios if s.scenario_id == "agent-indirect-ticket")
    runner, _, directory = make_agent_runner(attacker=attacker(max_proposals=8))
    summary = await runner.run(scenario, agent_manifest, run_id="prop-1", output_dir=directory)

    assert summary.status == "passed", summary.reason
    assert summary.proposals, "the attacker produced no proposals"
    rejected = [p for p in summary.proposals if not p.accepted]
    assert rejected, "no proposal was refused; the rejection path is untested"
    # Every refusal names why, and none of them stopped the run.
    assert all(p.reason_code for p in rejected)
    assert summary.teardown_complete

    events = [json.loads(line) for line in (directory / "evidence.jsonl").read_text().splitlines()]
    proposal_events = [e for e in events if e["kind"] == "proposal"]
    # Both legs propose, so the ledger carries at least one record per proposal per leg.
    assert len(proposal_events) >= len(summary.proposals)


async def test_a_cross_tenant_proposal_never_reaches_the_target(
    make_agent_runner: Make,
    agent_scenarios: list[Phase1Scenario],
    agent_manifest: AuthorizationManifest,
) -> None:
    scenario = next(s for s in agent_scenarios if s.scenario_id == "agent-indirect-ticket")
    runner, _, directory = make_agent_runner(attacker=attacker(max_proposals=12))
    summary = await runner.run(scenario, agent_manifest, run_id="prop-2", output_dir=directory)

    events = [json.loads(line) for line in (directory / "evidence.jsonl").read_text().splitlines()]
    for event in events:
        data = event.get("data") or {}
        target = data.get("target") if isinstance(data, dict) else None
        if isinstance(target, dict):
            assert target.get("tenant_id") != "org-b"
    assert summary.baseline is not None
    assert summary.baseline.unauthorized_side_effects >= 0
