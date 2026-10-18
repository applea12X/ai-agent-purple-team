# ADR 0012: Run attestations reuse the manifest's signing machinery and state their trust model

Status: accepted for Phase 4.

## Context

The PRD's release lane requires "signed run attestations in an in-toto/SLSA-shaped
purpose-built format". That phrase invites two failure modes: inventing cryptographic
constructions, or shipping a signature that attests nothing — signed by a key that lives next
to the thing it signs, over a statement no verifier checks.

## Decision

`RunAttestation` (schema 1.0.0) is a typed statement with the in-toto shape — subject,
materials, builder, byproducts — serialized through the existing JCS canonicalization path and
signed with the same Ed25519 machinery as the authorization manifest (ADR 0002). No new
cryptographic constructions.

- **Subject**: the SHA-256 of the bundle's sealed `inventory.json` bytes. The inventory carries
  the digest of every artifact, so the subject transitively covers the whole bundle; changing
  any artifact changes the subject.
- **Materials**: the code commit, the lockfile digest, every manifest and scenario digest found
  in the bundle, the corpus digest (over the sorted scenario digests), and the model pin ids —
  all recomputed from the bundle's own canonical documents, never asserted from memory.
- **Placement**: `attestation.json` and `attestation-public.pem` live beside the bundle but
  outside the inventory (like `inventory.json` itself), written only after the inventory is
  sealed. An attested bundle still verifies as an ordinary bundle.
- **Keys**: per-environment. A CI key lives in repository secrets; a developer key lives
  outside the repo; `key_provenance` records whether the signing key was `provided` or
  generated `ephemeral` for the run. An ephemeral key still binds bundle to materials but
  proves nothing about who ran it, and the statement says which it was rather than letting a
  reader assume. Manifest 1.4's `attestation_key_ids` names which key ids an engagement
  accepts.
- **Verification**: `verify-bundle --attestation` (or `verify-attestation`) checks the
  signature over the canonical statement bytes, then recomputes the subject from the bundle it
  sits beside. A reviewer can pin the expected public key explicitly.

## Trust model, stated at its real strength

A verified attestation proves that *this bundle* was bound to *these materials* under *this
key* — tamper-evidence and provenance. It is not SLSA certification, it does not prove the
build ran in any particular environment beyond what `builder` claims, and framework alignment
is not certification (PRD §10). The docs and the statement itself carry this framing.

## Verification of this ADR

`tests/phase4/test_attestation.py` covers the round trip and every tamper case: a modified
statement, a modified inventory, a wrong key, an incomplete bundle, and a missing attestation
each fail with a distinct error, and an attested bundle still verifies as a bundle.
