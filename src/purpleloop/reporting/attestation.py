"""Run attestations: a signed statement binding a bundle to what produced it (ADR 0012).

The subject is the SHA-256 of the bundle's ``inventory.json`` bytes. The inventory already
carries the digest of every artifact in the bundle, so the subject transitively covers all of
them: change any artifact and the subject changes. Signing reuses the Ed25519/JCS machinery the
authorization manifest already uses -- no new cryptographic constructions.

The attestation and its public key live beside the bundle's artifacts but outside the
inventory, the same way ``inventory.json`` itself does: they are written after the inventory is
sealed, and the verifier treats them as the statement *about* the bundle rather than part of it.

Stated trust model, at exactly its real strength: a verified attestation proves this bundle was
bound to these materials under this key, and nothing more. ``key_provenance`` says whether the
key was a provided per-environment key or generated for the run; an ephemeral key still binds
bundle to materials but proves nothing about who ran it.
"""

from __future__ import annotations

import base64
import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    load_pem_public_key,
)

from purpleloop.schemas.authorization import AuthorizationManifest
from purpleloop.schemas.common import digest_data
from purpleloop.schemas.phase1 import Phase1Scenario
from purpleloop.schemas.phase4 import AttestationMaterials, RunAttestation

ATTESTATION_FILE = "attestation.json"
ATTESTATION_KEY_FILE = "attestation-public.pem"

#: Bundle-root files that sit outside the artifact inventory: the inventory itself, and the
#: attestation statement about it.
UNINVENTORIED = frozenset({"inventory.json", ATTESTATION_FILE, ATTESTATION_KEY_FILE})


class AttestationError(ValueError):
    pass


def bundle_subject(directory: Path) -> tuple[str, Literal["run-bundle", "suite-bundle"]]:
    """The attestation subject: digest of the sealed inventory, and what kind of bundle it is."""
    inventory_path = directory / "inventory.json"
    if not inventory_path.exists():
        raise AttestationError("bundle has no inventory to attest")
    raw = json.loads(inventory_path.read_text())
    if not raw.get("complete"):
        raise AttestationError("only a complete, sealed bundle can be attested")
    kind: Literal["run-bundle", "suite-bundle"] = (
        "suite-bundle" if "suite.json" in raw.get("artifacts", {}) else "run-bundle"
    )
    return hashlib.sha256(inventory_path.read_bytes()).hexdigest(), kind


def collect_materials(
    directory: Path,
    *,
    code_commit: str | None = None,
    lockfile: Path | None = None,
) -> AttestationMaterials:
    """Materials from the bundle's own canonical documents; nothing is asserted from memory."""
    manifest_digests: set[str] = set()
    scenario_digests: list[str] = []
    pin_ids: set[str] = set()
    for manifest_path in sorted(directory.rglob("manifest.json")):
        manifest = AuthorizationManifest.model_validate_json(manifest_path.read_text())
        manifest_digests.add(manifest.manifest_digest())
        if manifest.phase3 is not None:
            pin_ids.update(pin.pin_id for pin in manifest.phase3.model_pins)
    for scenario_path in sorted(directory.rglob("scenario.json")):
        scenario = Phase1Scenario.model_validate_json(scenario_path.read_text())
        scenario_digests.append(scenario.digest())
    ordered = tuple(sorted(set(scenario_digests)))
    return AttestationMaterials(
        code_commit=code_commit,
        lockfile_digest=(
            hashlib.sha256(lockfile.read_bytes()).hexdigest()
            if lockfile is not None and lockfile.exists()
            else None
        ),
        corpus_digest=digest_data(list(ordered)) if ordered else None,
        manifest_digest=next(iter(manifest_digests)) if len(manifest_digests) == 1 else None,
        scenario_digests=ordered,
        model_pin_ids=tuple(sorted(pin_ids)),
    )


def sign_attestation(attestation: RunAttestation, private_key: Ed25519PrivateKey) -> RunAttestation:
    signature = base64.b64encode(private_key.sign(attestation.signed_bytes())).decode("ascii")
    return attestation.model_copy(update={"signature": signature})


def attest_bundle(
    directory: Path,
    private_key: Ed25519PrivateKey,
    *,
    key_id: str,
    builder: str,
    key_provenance: Literal["provided", "ephemeral"],
    code_commit: str | None = None,
    lockfile: Path | None = None,
    byproducts: dict[str, object] | None = None,
    now: datetime | None = None,
) -> RunAttestation:
    """Build, sign, and write the attestation and its public key beside the bundle."""
    subject_digest, subject_kind = bundle_subject(directory)
    attestation = sign_attestation(
        RunAttestation(
            subject_digest=subject_digest,
            subject_kind=subject_kind,
            builder=builder,
            key_provenance=key_provenance,
            created_at=now or datetime.now(UTC),
            materials=collect_materials(directory, code_commit=code_commit, lockfile=lockfile),
            byproducts=byproducts or {},  # type: ignore[arg-type]
            key_id=key_id,
            signature="",
        ),
        private_key,
    )
    (directory / ATTESTATION_FILE).write_text(
        json.dumps(
            attestation.model_dump(mode="json", exclude_none=True),
            sort_keys=True,
            indent=2,
            ensure_ascii=True,
        )
        + "\n",
        encoding="utf-8",
    )
    (directory / ATTESTATION_KEY_FILE).write_bytes(
        private_key.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    )
    return attestation


def verify_attestation(directory: Path, *, public_key_pem: bytes | None = None) -> RunAttestation:
    """Verify the attestation beside a bundle: signature first, then the recomputed subject.

    ``public_key_pem`` pins the expected key (a reviewer verifying against the repository's
    shipped key); when omitted, the key shipped beside the attestation is used, which proves
    integrity of the statement but leaves the key's identity to the reader.
    """
    attestation_path = directory / ATTESTATION_FILE
    if not attestation_path.exists():
        raise AttestationError("bundle carries no attestation")
    attestation = RunAttestation.model_validate_json(attestation_path.read_text())
    pem = public_key_pem or (directory / ATTESTATION_KEY_FILE).read_bytes()
    key = load_pem_public_key(pem)
    if not isinstance(key, Ed25519PublicKey):
        raise AttestationError("attestation key must be Ed25519")
    try:
        key.verify(
            base64.b64decode(attestation.signature, validate=True), attestation.signed_bytes()
        )
    except (InvalidSignature, ValueError) as exc:
        raise AttestationError("attestation signature is invalid") from exc
    subject_digest, subject_kind = bundle_subject(directory)
    if attestation.subject_digest != subject_digest:
        raise AttestationError("attested subject does not match the bundle inventory")
    if attestation.subject_kind != subject_kind:
        raise AttestationError("attested subject kind does not match the bundle")
    return attestation
