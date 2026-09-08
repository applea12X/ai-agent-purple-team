# ADR 0005: Persistent-fixture reset strategy

Status: accepted for Phase 2.

## Decision

`supportlab` reset restores state by **template database**, not by transactional rollback. The
seed is inserted once into a template (`supportlab_seed` on PostgreSQL; an in-memory template
connection on SQLite). Each paired leg starts from a fresh copy of that template
(`CREATE DATABASE ... TEMPLATE` on PostgreSQL; the SQLite backup API in process). The runner
recomputes the canonical snapshot hash after reset and refuses to start the paired leg unless it
equals the baseline hash, exactly as Phase 1 did.

## Rationale

A wrapping transaction rolled back per leg is faster but changes the isolation the application
runs under, which is itself part of what the workflow and approval scenarios exercise. The
template restore gives byte-identical starting state under the application's real declared
SERIALIZABLE isolation, and it is verified rather than trusted.

## Determinism under a real database

Four mitigations are enforced by tests, not convention:

- Every query that reaches scored output carries an explicit total ordering. A test greps the
  query layer (`SCORED_TABLES`, `TELEMETRY_QUERY`) for `ORDER BY`.
- Identifiers are application-assigned and seed-derived (or stable business references for
  approvals). No `SERIAL`/`IDENTITY` is used for any row that reaches scored output; rows created
  during a run use the injected logical tick.
- No `now()`, `random()`, or `gen_random_uuid()` appears in the schema or seed. A test asserts
  their absence.
- The snapshot hash is computed from a canonical ordered `SELECT` over the scored tables through
  the existing JCS path, never from `pg_dump`. The PostgreSQL and SQLite engines produce
  byte-identical seed hashes for the same seed; the acceptance record measures this.

## Consequence

Reset cost is one database copy per leg. Measured per-leg reset time is recorded in the
acceptance record. The database joins the internal network with no published ports and per-run
synthetic credentials that no attack credential can reference.
