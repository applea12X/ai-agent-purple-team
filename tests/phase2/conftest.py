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
    build_supportlab_runner,
    supportlab_manifest,
)
from purpleloop.schemas.authorization import AuthorizationManifest
from purpleloop.schemas.phase1 import Phase1Scenario, load_scenario, scenario_paths

SUPPORTLAB = ROOT / "scenarios" / "supportlab"


@pytest.fixture
def signing_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


@pytest.fixture
def supportlab_signed(signing_key: Ed25519PrivateKey) -> AuthorizationManifest:
    return supportlab_manifest(signing_key, seed=42)


@pytest.fixture
def supportlab_scenarios() -> list[Phase1Scenario]:
    return [load_scenario(path) for path in scenario_paths(SUPPORTLAB)]


@pytest.fixture
def make_supportlab_runner(
    tmp_path: Path, supportlab_signed: AuthorizationManifest, signing_key: Ed25519PrivateKey
) -> Callable[..., tuple[PurpleTeamRunner, InProcessSupportlab, Path]]:
    count = 0

    def make(**kwargs: Any) -> tuple[PurpleTeamRunner, InProcessSupportlab, Path]:
        nonlocal count
        count += 1
        directory = tmp_path / f"run-{count}"
        manifest = kwargs.pop("manifest", supportlab_signed)
        tokens = actor_credentials()
        control = "SUPPORTLAB-CONTROL-SECRET"
        fixture = InProcessSupportlab(tokens, control)
        runner = build_supportlab_runner(
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
