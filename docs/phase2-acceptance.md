# Phase 2 Acceptance Record

Date: September 7, 2026

Measured on a local macOS development environment with Docker Desktop (Docker Engine 29.7.2) and
pinned Chromium 145 via Playwright 1.58. Every number below was observed from a command that was
actually run, not inferred from a successful implementation. Results describe the eighteen
synthetic `supportlab` scenarios at their recorded versions and seed; they are not claims about
real models or production applications.

## Quality gate

Command: `make phase2-check`

- Ruff lint and format checks passed.
- mypy strict mode passed for 58 source files.
- 166 tests passed, 2 skipped. Branch-aware coverage 87.03% (floor 85%).
- The full suite also passed under `PYTHONHASHSEED=1`. CI runs the deterministic lane across five
  seeds (0, 1, 2, 3, 5).

The two skips are the container-lane isolation test and the Phase 1 container test, both gated
behind `PURPLELOOP_CONTAINER_TESTS=1` and reported separately below.

## Prior suites unchanged

Command: `uv run pytest tests/unit tests/contract tests/property tests/integration tests/acceptance tests/fault_injection tests/phase1 --no-cov`

- 133 tests passed, 1 skipped — the full Phase 0 and Phase 1 suites, unchanged. This equals the
  pre-Phase-2 total. Manifest 1.0 and 1.1 documents keep byte-identical canonical bytes: every
  Phase 2 field defaults to absent and is omitted from legacy canonical serialization.

## Corpus

Eighteen labelled scenarios (13 API, 5 browser) across object-, function-, and property-level
authorization; role boundaries; refund and export approval workflows; SSRF; unsafe upstream
consumption; and misconfiguration inventory. Six workflows are authored on both surfaces against a
shared oracle. All eighteen pass a full paired evaluation on both the deterministic (SQLite,
HTML-form driver) and container (PostgreSQL, Chromium) lanes.

## Deterministic replay and cross-engine determinism

- API lane replay: 1.0. Every scenario's normalized event and oracle hashes were identical across
  repeated in-process trials; no trial excluded.
- Browser lane replay (HTML-form driver): 1.0, reported separately. The driver is bit-exact
  because it renders the fixture's server-side HTML in process. The Playwright Chromium driver runs
  only in the container/browser lane and is a named coverage exclusion below; its replay is not
  folded into the API number.
- The PostgreSQL and SQLite engines produced byte-identical seed hashes for seed 42
  (`5c270cdda4ecb931d37a1285636cc84f609fbc1c3d467d05a0116cca235d1b3d`).

## Isolation and evidence completeness

Command: `uv run pytest tests/phase2/test_supportlab_acceptance.py`

- 100 consecutive isolated in-process runs across all eighteen scenarios: 0 failures, 18 distinct
  scenarios, no cross-run state leakage (a fresh run of each scenario started from the identical
  seeded state hash), 31s wall time. Every failure would have been reported, never rerun until
  clean.
- Minimum evidence-field completeness across those runs: 1.0 (threshold ≥ 0.99), computed by the
  tested `evidence_completeness` metric over required per-kind fields.
- Zero unintended cross-tenant access by the harness: every paired replay leg recorded
  `unauthorized_side_effects == 0`, and ownership-mismatch mutations are denied at the policy
  boundary before any I/O.

## Reset strategy

- Deterministic lane (SQLite backup restore): mean 0.03 ms over 20 resets, each verified
  byte-identical to the seed hash.
- Container lane (PostgreSQL `CREATE DATABASE ... TEMPLATE`): mean 23.2 ms over 10 resets, each
  verified byte-identical, under the application's declared SERIALIZABLE isolation. Reset time is
  well within the per-leg budget at 100-run scale.

## Cross-surface agreement

- 2 shared-oracle groups (cross-tenant ticket and cross-tenant document), each with an API and a
  browser member, agreed on baseline and defended-replay verdicts. Disagreements: none.
  Disagreements are listed per group, never averaged into a rate.

## Resource estimate versus actual

- The pre-run estimate's deterministic dimensions — requests, records, and browser contexts —
  matched actual use exactly for every scenario (delta 0%). Wall time is reported as an estimate,
  not a bound; the token and API-cost form of this checkpoint is Phase 3, where real model calls
  first exist.

## Container isolation

Command: `PURPLELOOP_CONTAINER_TESTS=1 uv run pytest tests/phase2/test_supportlab_isolation.py --no-cov`

- Compose contract: read-only root, tmpfs state, all capabilities dropped, `no-new-privileges`,
  internal-only network for the fixture, upstream, and database; the database has no published
  ports; only the loopback-bound ingress relay bridges to the frontend, and it carries no
  environment.
- Live container: non-root user, external egress to `1.1.1.1:443` refused, and a customer
  credential presented to `/control/snapshot` rejected with HTTP 403 while the control credential
  succeeds through the loopback relay. The database is unreachable from any attack credential
  because it has no published port and a per-run credential no adapter is given.

## Offline container demo

Command: `make supportlab-demo`

- Eighteen container-backed paired evaluations on PostgreSQL, with the five browser scenarios
  driven through Chromium — all passed. The suite bundle and every scenario directory verified
  (`verify-bundle` returned 18 scenarios, complete).
- Teardown removed all `supportlab` containers, volumes, and networks after each scenario;
  `docker ps -a` listed none.
- No cloud credentials and no network model provider were used. Base images are pinned by digest
  (`python:3.12-slim`, `postgres:16-alpine`, `ghcr.io/astral-sh/uv:0.11.7`), so a rebuild whose
  layers are cached cannot fail on registry DNS; a build failure is reported as
  `partial evidence: <path>`, distinct from an evaluation failure.

## Browser emergency stop

- The browser is an out-of-process child, so Phase 0's in-process cancellation p99 does not
  transfer. Browser-lane emergency stop is measured on its own: a kill-switch termination during a
  browser flow tears the driver down through the adapter's `finally` path and closes the fixture.
  The measurement is recorded in `artifacts/phase2-emergency-stop.json`.

## Defects found and fixed during acceptance

- **Redactor masked a defense-config value.** The flaw flag named `function_authorization` matched
  the redactor's sensitive-key heuristic (the substring "authorization"), so its boolean value was
  redacted to `[REDACTED]` and the runner's defense-configuration verification failed for exactly
  the four function-level scenarios. Fixed by renaming the flag to `function_guard`; the redactor
  is a security control and was not weakened.
- **Approval identifiers were seed-derived but referenced by literal key.** Scenarios named
  `approval-refund-a`, which the fixture assigned a seed-derived id, so the "clean" refund was
  never actually approved and the defended replay regressed. Fixed by giving approvals stable
  business reference identifiers; they remain application-assigned, never sequence-generated.
- **Migrations were not packaged into the wheel.** The container image located migrations by a
  source-tree relative path that does not exist in `site-packages`, so PostgreSQL seeding failed
  with `relation "orgs" does not exist`. Fixed by packaging the canonical DDL as a Python module and
  generating the `.sql` file from it; a test asserts the two never drift.

Each defect was found by a command that failed, and each fix is covered by a test that fails when
reverted.

## Coverage exclusions (container/browser lanes only)

Named here the way `relay.py` was in Phase 1. These execute only in the container or browser lane
and are marked `# pragma: no cover` accordingly:

- `src/purpleloop/adapters/browser.py` — `PlaywrightDriver` and `PlaywrightSession` (browser lane;
  the exact `HtmlFormDriver` is fully covered in the deterministic lane).
- `src/purpleloop/runtime/supportlab.py` — `ServedSupportlab` (host browser lane over real sockets)
  and `ComposeSupportlab` (container lane).
- `src/purpleloop/supportlab_cli.py` — the `supportlab-demo` command body and the compose branch of
  `run_one`.
- `src/purpleloop/fixture/supportlab/relay.py` and `upstream.py` `serve()` entry points execute
  only inside the container lane, as the Phase 1 relay does.

## Known limits

- Browser bit-level determinism is not claimed. The browser lane reports its own replay rate; the
  HTML-form driver is exact, and the Chromium driver's determinism rests on frozen clock, fixed
  viewport/locale/timezone, disabled animations, and scoring only from state and typed DOM
  assertions — not on reproducible pixels.
- Detection delay uses injected logical ticks and is not a claim about production latency. Budget
  tokens are reserved capacity, not cloud billing; Phase 2 remains offline for models.
- A passing run is evidence about these exact fixtures, seed, and defenses only. It does not prove a
  target or model is secure, and harness authorization never makes an application authorization
  failure legitimate.
