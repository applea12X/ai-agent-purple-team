# ADR 0007: Manifest-derived resource ownership

Status: accepted for Phase 2.

## Decision

Resource ownership is resolved from the **signed manifest**, never from the application under test.
Manifest 1.2 declares an `ownership` scope: explicit resource-ID sets per tenant, tied to the
deterministic fixture seed. The kernel resolves `resource → tenant` from that signed data alone.

## Rationale

Phase 1 bound a resource to a tenant through a literal map inside a tool definition. With two
organizations and a seeded database, that map cannot be enumerated in code by hand — but the
obvious fix, asking the fixture who owns a row, is wrong: the fixture is the untrusted component
under test. A compromised or buggy fixture could then authorize the harness against a row it should
never touch.

The seed is deterministic precisely so ownership is enumerable at signing time. `supportlab_manifest`
computes the ownership sets from the same seed function the fixture uses, so the signed manifest and
the seeded data agree by construction, and a test asserts the PostgreSQL and SQLite engines produce
the same seed hash.

## Consequence

The policy engine denies an action whose target resource is unsigned (`RESOURCE_NOT_SIGNED`) or
whose signed owner differs from the claimed target tenant (`RESOURCE_OWNERSHIP_MISMATCH`), before
any I/O. The fixture's own opinion about ownership is recorded as observed data and is exactly what
the oracle evaluates; it never feeds the authorization decision. This preserves the invariant that
harness authorization and target vulnerability are independent facts. Ownership is chosen as
explicit ID sets rather than signed ranges: at fixture scale they are simpler to audit, and the
seed makes them enumerable.
