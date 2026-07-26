from __future__ import annotations

from datetime import UTC, datetime

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import ValidationError

from purpleloop.control.manifest import ManifestError, ManifestVerifier
from purpleloop.schemas import ActionRequest, AuthorizationManifest


def test_signed_manifest_verifies_and_is_canonical(
    manifest: AuthorizationManifest, private_key: Ed25519PrivateKey
) -> None:
    verifier = ManifestVerifier({"test-key": private_key.public_key()})
    assert verifier.verify(manifest, now=datetime(2026, 7, 25, tzinfo=UTC)) is manifest
    rebuilt = AuthorizationManifest.model_validate_json(manifest.model_dump_json())
    assert rebuilt.manifest_digest() == manifest.manifest_digest()
    assert rebuilt.canonical_bytes() == manifest.canonical_bytes()


def test_manifest_mutation_invalidates_signature(
    manifest: AuthorizationManifest, private_key: Ed25519PrivateKey
) -> None:
    mutated = manifest.model_copy(update={"owner": "attacker"})
    with pytest.raises(ManifestError, match="signature") as error:
        ManifestVerifier({"test-key": private_key.public_key()}).verify(mutated)
    assert error.value.reason_code == "INVALID_SIGNATURE"


@pytest.mark.parametrize(
    ("now", "reason"),
    [
        (datetime(2025, 1, 1, tzinfo=UTC), "NOT_YET_VALID"),
        (datetime(2028, 1, 1, tzinfo=UTC), "EXPIRED_MANIFEST"),
    ],
)
def test_manifest_time_window_fails_closed(
    manifest: AuthorizationManifest,
    private_key: Ed25519PrivateKey,
    now: datetime,
    reason: str,
) -> None:
    with pytest.raises(ManifestError) as error:
        ManifestVerifier({"test-key": private_key.public_key()}).verify(manifest, now=now)
    assert error.value.reason_code == reason


def test_revoked_manifest_fails_closed(
    manifest: AuthorizationManifest, private_key: Ed25519PrivateKey
) -> None:
    verifier = ManifestVerifier(
        {"test-key": private_key.public_key()},
        frozenset({manifest.manifest_digest()}),
    )
    with pytest.raises(ManifestError) as error:
        verifier.verify(manifest)
    assert error.value.reason_code == "REVOKED_MANIFEST"


def test_unknown_fields_are_rejected(manifest: AuthorizationManifest) -> None:
    payload = manifest.model_dump(mode="json")
    payload["unexpected"] = "value"
    with pytest.raises(ValidationError):
        AuthorizationManifest.model_validate(payload)


def test_phase0_action_rejects_write(action: ActionRequest) -> None:
    payload = action.model_dump(mode="json")
    payload["method"] = "POST"
    with pytest.raises(ValidationError):
        ActionRequest.model_validate(payload)
