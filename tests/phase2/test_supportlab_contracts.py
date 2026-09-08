from __future__ import annotations

from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import ValidationError

from purpleloop.control.lanes import SUPPORTLAB_LANE
from purpleloop.control.phase2_tools import DATABASE_HANDLE
from purpleloop.control.plan_compiler import PlanError, compile_plan, compile_step
from purpleloop.control.policy import DefaultDenyPolicy
from purpleloop.runtime.supportlab import supportlab_manifest
from purpleloop.schemas.authorization import AuthorizationManifest
from purpleloop.schemas.phase1 import Phase1Scenario
from purpleloop.schemas.phase2 import Phase2Grants


def _scenario(scenarios: list[Phase1Scenario], sid: str) -> Phase1Scenario:
    return next(s for s in scenarios if s.scenario_id == sid)


def test_manifest_12_backward_compatible_and_gated() -> None:
    key = Ed25519PrivateKey.generate()
    manifest = supportlab_manifest(key, seed=42)
    assert manifest.schema_version == "1.2.0" and manifest.phase2 is not None
    # Phase 2 grants require version 1.2.
    with pytest.raises(ValidationError):
        AuthorizationManifest.model_validate({**manifest.model_dump(), "schema_version": "1.1.0"})
    # The database credential can never appear as an attack credential handle.
    with pytest.raises(ValidationError):
        bad = manifest.model_dump()
        bad["credential_handles"] = sorted({*manifest.credential_handles, DATABASE_HANDLE})
        bad["credential_scopes"][DATABASE_HANDLE] = ["ticket.read"]
        AuthorizationManifest.model_validate(bad)


def test_ownership_resolves_from_signed_data_not_the_fixture() -> None:
    key = Ed25519PrivateKey.generate()
    manifest = supportlab_manifest(key, seed=42)
    owned_b = sorted(
        next(s for s in manifest.phase2.ownership if s.tenant_id == "org-b").resource_ids
    )
    assert manifest.resource_owner(owned_b[0]) == "org-b"
    assert manifest.resource_owner("not-a-signed-resource") is None


def test_ownership_rejects_overlap_and_unknown_tenant() -> None:
    with pytest.raises(ValidationError):
        Phase2Grants(
            ownership_seed=1,
            ownership=(
                {"tenant_id": "org-a", "resource_ids": ["r1"]},
                {"tenant_id": "org-b", "resource_ids": ["r1"]},
            ),
            database_credential_handle="db",
            containment_prefix="purpleloop-x",
        )


def test_browser_steps_reject_free_form_instructions(
    supportlab_scenarios: Any, supportlab_signed: Any
) -> None:
    scenario = _scenario(supportlab_scenarios, "bola-ticket-ui")
    step = scenario.attack_steps[0]
    for payload in ({"script": "alert(1)"}, {"url": "http://evil"}, {"selector": ".x"}):
        poisoned = step.model_copy(update={"arguments": payload})
        with pytest.raises(PlanError):
            compile_step(poisoned, scenario, supportlab_signed, lane=SUPPORTLAB_LANE)


def test_plan_rejects_wrong_version_and_seed(
    supportlab_scenarios: Any, supportlab_signed: Any
) -> None:
    scenario = _scenario(supportlab_scenarios, "bola-ticket")
    # A manifest whose ownership seed differs from the scenario seed is refused.
    key = Ed25519PrivateKey.generate()
    other = supportlab_manifest(key, seed=7)
    with pytest.raises(PlanError):
        compile_plan(scenario, other, lane=SUPPORTLAB_LANE)


def test_ownership_mismatch_denied_before_io(
    supportlab_scenarios: Any, supportlab_signed: Any
) -> None:
    scenario = _scenario(supportlab_scenarios, "bola-ticket")
    action = compile_step(
        scenario.attack_steps[0], scenario, supportlab_signed, lane=SUPPORTLAB_LANE
    )
    # The attack reads an org-b ticket as org-b (a signed exercise). Claiming org-a ownership of an
    # org-b resource must be denied: ownership comes from signed data, not the target claim.
    mutated = action.model_copy(
        update={"target": action.target.model_copy(update={"tenant_id": "org-a"})}
    )
    decision = DefaultDenyPolicy(SUPPORTLAB_LANE.tools).evaluate(supportlab_signed, mutated)
    assert not decision.permitted
    assert decision.reason_code == "RESOURCE_OWNERSHIP_MISMATCH"


def test_database_credential_handle_denied(
    supportlab_scenarios: Any, supportlab_signed: Any
) -> None:
    scenario = _scenario(supportlab_scenarios, "bola-ticket")
    action = compile_step(
        scenario.clean_steps[0], scenario, supportlab_signed, lane=SUPPORTLAB_LANE
    )
    mutated = action.model_copy(update={"credential_handle": DATABASE_HANDLE})
    decision = DefaultDenyPolicy(SUPPORTLAB_LANE.tools).evaluate(supportlab_signed, mutated)
    assert not decision.permitted


def test_actor_binding_is_trusted(supportlab_scenarios: Any, supportlab_signed: Any) -> None:
    scenario = _scenario(supportlab_scenarios, "bola-ticket")
    forged = scenario.model_copy(
        update={
            "actor": scenario.actor.model_copy(update={"credential_handle": "supportlab-admin-a"})
        }
    )
    with pytest.raises(PlanError):
        compile_plan(forged, supportlab_signed, lane=SUPPORTLAB_LANE)
