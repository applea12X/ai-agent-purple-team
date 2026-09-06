"""Canonical bytes must not depend on set iteration order.

`frozenset` fields serialize to JSON arrays, and JCS preserves array order. Before `order_sets`,
canonical bytes depended on `PYTHONHASHSEED` and on how a set was built, so a signature or digest
taken before a JSON round-trip could disagree with one taken after it.
"""

from __future__ import annotations

from datetime import UTC, datetime

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from purpleloop.control.manifest import ManifestVerifier
from purpleloop.runtime.demo import demo_manifest
from purpleloop.schemas.authorization import AuthorizationManifest
from purpleloop.schemas.common import StrictModel

PINNED = datetime(2026, 1, 1, tzinfo=UTC)
KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))


class Ordered(StrictModel):
    labels: frozenset[str]
    sequence: tuple[str, ...]


def test_json_round_trip_preserves_signature_and_digest() -> None:
    manifest = demo_manifest(KEY, now=PINNED)
    restored = AuthorizationManifest.model_validate_json(manifest.model_dump_json())
    assert restored.signed_bytes() == manifest.signed_bytes()
    assert restored.manifest_digest() == manifest.manifest_digest()
    ManifestVerifier({"demo-key": KEY.public_key()}).verify(restored, now=PINNED)


def test_digest_is_stable_for_identical_content() -> None:
    assert demo_manifest(KEY, now=PINNED).manifest_digest() == (
        "663c1dcbcce3cff2f7163443ccc4b33d2fc3621106503f6daa0157eca02966dc"
    )


def test_set_insertion_order_does_not_change_canonical_bytes() -> None:
    labels = ["gamma", "alpha", "beta", "delta", "epsilon"]
    first = Ordered(labels=frozenset(labels), sequence=("a", "b"))
    second = Ordered(labels=frozenset(reversed(labels)), sequence=("a", "b"))
    assert first.canonical_bytes() == second.canonical_bytes()
    assert b'"alpha","beta","delta","epsilon","gamma"' in first.canonical_bytes()


def test_ordered_tuples_are_not_reordered() -> None:
    model = Ordered(labels=frozenset({"x"}), sequence=("gamma", "alpha", "beta"))
    assert b'"gamma","alpha","beta"' in model.canonical_bytes()
