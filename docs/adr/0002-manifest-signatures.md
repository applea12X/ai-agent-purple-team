# ADR 0002: Canonical signed authorization manifests

## Decision

Authorization manifests are strict Pydantic models serialized with RFC 8785 canonical JSON and signed with Ed25519. The signature is excluded from the signed payload; the manifest digest is SHA-256 over the same canonical payload.

## Rationale

Canonical bytes prevent parser and key-order differences from changing verification semantics. Ed25519 provides compact deterministic signatures with a small API surface.

## Consequence

Unknown fields, non-UTC times, ambiguous targets, unsupported effects, invalid signatures, untrusted keys, expired manifests, and locally revoked digests fail closed.
