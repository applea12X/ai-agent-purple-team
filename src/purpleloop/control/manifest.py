from __future__ import annotations

import base64
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol

import yaml
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import ValidationError

from purpleloop.schemas.authorization import AuthorizationManifest


class ManifestError(ValueError):
    def __init__(self, reason_code: str, message: str) -> None:
        self.reason_code = reason_code
        super().__init__(message)


class RevocationProvider(Protocol):
    def is_revoked(self, digest: str) -> bool: ...


class InMemoryRevocationProvider:
    def __init__(
        self,
        revoked_digests: frozenset[str] = frozenset(),
        *,
        available: bool = True,
    ) -> None:
        self.revoked_digests = set(revoked_digests)
        self.available = available

    def is_revoked(self, digest: str) -> bool:
        if not self.available:
            raise ManifestError("REVOCATION_UNAVAILABLE", "revocation status is unavailable")
        return digest in self.revoked_digests


class ManifestVerifier:
    def __init__(
        self,
        public_keys: dict[str, Ed25519PublicKey],
        revoked_digests: frozenset[str] = frozenset(),
        revocations: RevocationProvider | None = None,
    ) -> None:
        self._public_keys = dict(public_keys)
        self._revocations = revocations or InMemoryRevocationProvider(revoked_digests)

    def verify(
        self, manifest: AuthorizationManifest, *, now: datetime | None = None
    ) -> AuthorizationManifest:
        current = (now or datetime.now(UTC)).astimezone(UTC)
        key = self._public_keys.get(manifest.key_id)
        if key is None:
            raise ManifestError("UNKNOWN_SIGNING_KEY", "manifest signing key is not trusted")
        try:
            signature = base64.b64decode(manifest.signature, validate=True)
            key.verify(signature, manifest.signed_bytes())
        except (InvalidSignature, ValueError) as exc:
            raise ManifestError("INVALID_SIGNATURE", "manifest signature is invalid") from exc
        if self._revocations.is_revoked(manifest.manifest_digest()):
            raise ManifestError("REVOKED_MANIFEST", "manifest has been revoked")
        if current < manifest.valid_from:
            raise ManifestError("NOT_YET_VALID", "manifest is not yet valid")
        if current >= manifest.valid_until:
            raise ManifestError("EXPIRED_MANIFEST", "manifest has expired")
        return manifest


def load_manifest(path: Path) -> AuthorizationManifest:
    try:
        raw = path.read_text(encoding="utf-8")
        data: Any = (
            yaml.safe_load(raw) if path.suffix.lower() in {".yaml", ".yml"} else json.loads(raw)
        )
        return AuthorizationManifest.model_validate(data)
    except (OSError, json.JSONDecodeError, yaml.YAMLError, ValidationError) as exc:
        raise ManifestError("INVALID_MANIFEST", "manifest could not be loaded") from exc


def sign_manifest(manifest: AuthorizationManifest, private_key: Any) -> AuthorizationManifest:
    signature = base64.b64encode(private_key.sign(manifest.signed_bytes())).decode("ascii")
    return manifest.model_copy(update={"signature": signature})
