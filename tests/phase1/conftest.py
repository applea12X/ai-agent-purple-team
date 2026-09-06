from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from purpleloop.control.manifest import ManifestVerifier
from purpleloop.runtime.demo import ROOT, build_runner, demo_manifest
from purpleloop.runtime.fixture import InProcessFixture
from purpleloop.runtime.runner import PurpleTeamRunner
from purpleloop.schemas.authorization import AuthorizationManifest
from purpleloop.schemas.phase1 import Phase1Scenario, load_scenario


@pytest.fixture
def signing_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


@pytest.fixture
def phase1_manifest(signing_key: Ed25519PrivateKey) -> AuthorizationManifest:
    return demo_manifest(signing_key)


@pytest.fixture
def scenarios() -> list[Phase1Scenario]:
    return [load_scenario(path) for path in sorted((ROOT / "scenarios/phase1").glob("*.yaml"))]


@pytest.fixture
def make_runner(
    tmp_path: Path, phase1_manifest: AuthorizationManifest, signing_key: Ed25519PrivateKey
) -> Callable[..., tuple[PurpleTeamRunner, InProcessFixture, Path]]:
    count = 0

    def make(**kwargs: Any) -> tuple[PurpleTeamRunner, InProcessFixture, Path]:
        nonlocal count
        count += 1
        directory = tmp_path / f"run-{count}"
        manifest = kwargs.pop("manifest", phase1_manifest)
        fixture = InProcessFixture("CUSTOMER-SECRET-123", "CONTROL-SECRET-456")
        runner = build_runner(
            directory,
            manifest,
            ManifestVerifier({"demo-key": signing_key.public_key()}),
            customer="CUSTOMER-SECRET-123",
            control="CONTROL-SECRET-456",
            fixture=fixture,
            **kwargs,
        )
        return runner, fixture, directory

    return make
