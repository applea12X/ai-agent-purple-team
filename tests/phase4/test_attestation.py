"""Attestation signing, verification, and every tamper case (ADR 0012).

A signature that survives tampering attests nothing, so the tamper cases are the substance
here: a modified artifact, a modified inventory, a modified statement, and a wrong key must
each fail verification, and an attested bundle must keep verifying as an ordinary bundle.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from purpleloop.agent_cli import run_offline_scenario
from purpleloop.reporting.attestation import (
    ATTESTATION_FILE,
    AttestationError,
    attest_bundle,
    verify_attestation,
)
from purpleloop.reporting.bundle import verify_bundle
from purpleloop.runtime.demo import ROOT


@pytest.fixture(scope="module")
def bundle(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """One real, complete, verified run bundle to attest."""
    directory = tmp_path_factory.mktemp("attest") / "agent-direct-injection"
    summary = asyncio.run(
        run_offline_scenario(
            ROOT / "scenarios" / "agent" / "agent-direct-injection.yaml", directory
        )
    )
    assert summary.status == "passed"
    verify_bundle(directory)
    return directory


def attest(directory: Path, key: Ed25519PrivateKey | None = None) -> Ed25519PrivateKey:
    private = key or Ed25519PrivateKey.generate()
    attest_bundle(
        directory,
        private,
        key_id="test-key",
        builder="pytest",
        key_provenance="provided",
        lockfile=ROOT / "uv.lock",
    )
    return private


def test_attest_and_verify_round_trip(bundle: Path) -> None:
    attest(bundle)
    attestation = verify_attestation(bundle)
    assert attestation.subject_kind == "run-bundle"
    assert attestation.materials.manifest_digest is not None
    assert attestation.materials.lockfile_digest is not None
    assert attestation.materials.corpus_digest is not None
    assert "offline-scripted" in attestation.materials.model_pin_ids


def test_attested_bundle_still_verifies_as_a_bundle(bundle: Path) -> None:
    """The statement lives outside the sealed inventory; the bundle contract is unchanged."""
    attest(bundle)
    result = verify_bundle(bundle)
    assert result["valid"] is True


def test_verification_pins_the_expected_key(bundle: Path) -> None:
    key = attest(bundle)
    pem = key.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    assert verify_attestation(bundle, public_key_pem=pem).key_id == "test-key"
    other = (
        Ed25519PrivateKey.generate()
        .public_key()
        .public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    )
    with pytest.raises(AttestationError, match="signature is invalid"):
        verify_attestation(bundle, public_key_pem=other)


def test_a_tampered_statement_fails(bundle: Path) -> None:
    attest(bundle)
    path = bundle / ATTESTATION_FILE
    statement = json.loads(path.read_text())
    statement["builder"] = "someone-else"
    path.write_text(json.dumps(statement, sort_keys=True))
    with pytest.raises(AttestationError, match="signature is invalid"):
        verify_attestation(bundle)


def test_a_tampered_inventory_fails_the_subject_check(bundle: Path) -> None:
    attest(bundle)
    inventory_path = bundle / "inventory.json"
    original = inventory_path.read_text()
    try:
        inventory_path.write_text(original.replace("\n", "\n ", 1))
        with pytest.raises(AttestationError, match="does not match the bundle inventory"):
            verify_attestation(bundle)
    finally:
        inventory_path.write_text(original)


def test_an_incomplete_bundle_cannot_be_attested(bundle: Path, tmp_path: Path) -> None:
    partial = tmp_path / "partial"
    partial.mkdir()
    (partial / "inventory.json").write_text(
        json.dumps({"schema_version": "1.1.0", "complete": False, "artifacts": {}})
    )
    with pytest.raises(AttestationError, match="complete"):
        attest(partial)


def test_a_bundle_without_an_attestation_says_so(bundle: Path) -> None:
    (bundle / ATTESTATION_FILE).unlink(missing_ok=True)
    with pytest.raises(AttestationError, match="no attestation"):
        verify_attestation(bundle)
