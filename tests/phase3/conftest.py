from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from purpleloop.control.manifest import ManifestVerifier
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
