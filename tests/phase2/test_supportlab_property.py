"""Property matrix: every unauthorized mutation of a compiled attack action is denied before I/O."""

from __future__ import annotations

from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from purpleloop.control.lanes import SUPPORTLAB_LANE
from purpleloop.control.phase2_tools import CONTROL_HANDLE, DATABASE_HANDLE
from purpleloop.control.plan_compiler import compile_step
from purpleloop.control.policy import DefaultDenyPolicy
from purpleloop.runtime.demo import ROOT
from purpleloop.runtime.supportlab import supportlab_manifest
from purpleloop.schemas.action import SideEffectClass
from purpleloop.schemas.phase1 import load_scenario


@settings(max_examples=8, suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(
    kind=st.sampled_from(
        ["host", "tenant", "resource", "method", "arguments", "effect", "credential", "database"]
    )
)
def test_mutations_denied_before_io(kind: str) -> None:
    scenario = load_scenario(ROOT / "scenarios/supportlab/mass-assignment-credit.yaml")
    manifest = supportlab_manifest(Ed25519PrivateKey.generate(), seed=42)
    action = compile_step(scenario.attack_steps[0], scenario, manifest, lane=SUPPORTLAB_LANE)
    changes: dict[str, Any] = {
        "host": {
            "target": action.target.model_copy(
                update={"url": action.target.url.replace("127.0.0.1", "10.0.0.9")}
            )
        },
        "tenant": {"target": action.target.model_copy(update={"tenant_id": "org-b"})},
        "resource": {
            "target": action.target.model_copy(update={"resource_id": "unsigned-resource"})
        },
        "method": {"method": "DELETE"},
        "arguments": {"arguments": {"unknown": True}},
        "effect": {"side_effect": SideEffectClass.DESTRUCTIVE},
        # The control handle is a real handle, but its scope excludes data operations.
        "credential": {"credential_handle": CONTROL_HANDLE},
        "database": {"credential_handle": DATABASE_HANDLE},
    }
    decision = DefaultDenyPolicy(SUPPORTLAB_LANE.tools).evaluate(
        manifest, action.model_copy(update=changes[kind])
    )
    assert not decision.permitted
