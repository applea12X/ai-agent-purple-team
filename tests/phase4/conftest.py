"""Agent-lane fixtures for Phase 4 tests.

These mirror ``tests/phase3/conftest.py`` rather than importing it: ``tests`` is not a package,
and the Phase 3 suite is not edited, so Phase 4 carries its own copy of the same construction.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from purpleloop.control.attacker import BoundedAttacker
from purpleloop.control.manifest import ManifestVerifier
from purpleloop.control.phase3_tools import INTENT_OPERATIONS
from purpleloop.runtime.demo import ROOT
from purpleloop.runtime.runner import PurpleTeamRunner
from purpleloop.runtime.supportlab import (
    KEY_ID,
    InProcessSupportlab,
    actor_credentials,
    build_agent_runner,
    supportlab_agent_manifest,
)
from purpleloop.schemas.authorization import AuthorizationManifest
from purpleloop.schemas.phase1 import Phase1Scenario, load_scenario, scenario_paths

AGENT_SCENARIOS = ROOT / "scenarios" / "agent"


@pytest.fixture
def signing_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


@pytest.fixture
def agent_manifest(signing_key: Ed25519PrivateKey) -> AuthorizationManifest:
    return supportlab_agent_manifest(signing_key, seed=42)


@pytest.fixture
def agent_scenarios() -> list[Phase1Scenario]:
    return [load_scenario(path) for path in scenario_paths(AGENT_SCENARIOS)]


@pytest.fixture
def demo_attacker(agent_manifest: AuthorizationManifest) -> Callable[[], BoundedAttacker]:
    """The attacker exactly as ``agent-demo`` configures it, built fresh per run."""
    grants = agent_manifest.phase3
    assert grants is not None

    def build() -> BoundedAttacker:
        return BoundedAttacker(
            max_proposals=grants.max_attacker_proposals,
            max_depth=grants.max_attacker_depth,
            operations=sorted(INTENT_OPERATIONS),
            own_tenant="org-a",
            other_tenants=("org-b",),
            resource_id="admin-a",
        )

    return build


@pytest.fixture
def make_agent_runner(
    tmp_path: Path, agent_manifest: AuthorizationManifest, signing_key: Ed25519PrivateKey
) -> Callable[..., tuple[PurpleTeamRunner, InProcessSupportlab, Path]]:
    count = 0

    def make(**kwargs: Any) -> tuple[PurpleTeamRunner, InProcessSupportlab, Path]:
        nonlocal count
        count += 1
        directory = tmp_path / f"agent-run-{count}"
        manifest = kwargs.pop("manifest", agent_manifest)
        tokens = actor_credentials()
        control = "SUPPORTLAB-CONTROL-SECRET"
        fixture = InProcessSupportlab(tokens, control)
        runner = build_agent_runner(
            directory,
            manifest,
            ManifestVerifier({KEY_ID: signing_key.public_key()}),
            actor_tokens=tokens,
            control=control,
            fixture=fixture,
            **kwargs,
        )
        return runner, fixture, directory

    return make
