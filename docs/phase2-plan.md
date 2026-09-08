# Phase 2 implementation — realistic SaaS and browser lane

The Phase 2 section of [PRD.md](../planning/PRD.md) is authoritative. This document describes the
implemented design and supersedes the working plan in
[planning/phase2-plan.md](../planning/phase2-plan.md). Measured results are in
[phase2-acceptance.md](phase2-acceptance.md), not inferred here.

## What Phase 2 adds, and what it does not touch

Phase 2 replaces the single in-memory Phase 1 fixture with `supportlab`: a persistent,
multi-organization SaaS application backed by a real database, and adds a browser surface. It does
this without changing the authority model. `SafetyRuntime` stays the per-action boundary and
`PurpleTeamRunner` stays the lifecycle owner. The Phase 1 fixture, its five scenarios, and its CI
lane remain in the tree, green, and unchanged, so the deterministic loop stays a fast regression
lane. Phase 0's and Phase 1's suites pass unchanged and existing manifests keep byte-identical
digests, because every new field defaults to absent and is omitted from legacy canonical bytes.

## Lanes

A `LaneContract` names the trusted bindings that differ between fixtures: tool registry, defense
registry, signed asset expectations, actor bindings, registered cross-tenant exercises, seed
arguments, resource resolver, and resource calibration. The runner and compiler are parameterized
by a lane. The Phase 1 lane keeps exactly its earlier behavior; the `supportlab` lane adds a
second fixture and a browser surface without a second runner. This is the mechanism that lets one
lifecycle owner drive both fixtures.

## Contracts (all additive and versioned)

- **Manifest 1.2** adds `phase2` grants: signed resource ownership tied to the deterministic seed,
  a database credential scope no attack credential can reference, a per-run containment prefix,
  browser-capable assets, signed subresource origins, and a browser-context cap. A 1.2 manifest
  still satisfies every Phase 1 loopback-fixture rule.
- **Scenario 1.2** adds a `surface` field (`api` | `browser` | `both`), typed browser steps, and a
  `shared_oracle` reference so cross-surface scenarios are scored by one specification. An inline
  oracle that disagrees with the shared one is an error, not a silent override.
- **Resource ownership** ([ADR 0007](adr/0007-manifest-derived-resource-ownership.md)) comes from
  the signed manifest, never from the fixture. The seed is deterministic precisely so ownership is
  enumerable at signing time. The fixture's opinion is observed data the oracle evaluates.
- **Browser action types** — navigate, fill, click, read — resolve from a signed asset ID and a
  trusted flow registry. Free-form JavaScript, URLs, and selectors are rejected at compile time.

## supportlab

Two organizations; five users spanning customer, agent, and admin; tickets, documents, refunds,
exports, approvals, an audit log, and canary records; every value synthetic. The data layer is
PostgreSQL in the container lane and in-process SQLite in the deterministic lane, behind one
engine-independent surface. The two engines produce byte-identical seed hashes for the same seed.

Determinism under a real database follows four mitigations, each enforced by a test rather than a
convention ([ADR 0005](adr/0005-persistent-fixture-reset.md)): total ordering on every scored
query, seed-derived application-assigned identifiers with no sequences in scored output, no
`now()`/`random()`/`gen_random_uuid()` in schema or seed, and a snapshot hash taken from a
canonical ordered `SELECT` through the JCS path. Reset is a template-database restore, verified by
snapshot-hash equality before each paired leg.

Six flaw classes, each a named configuration value whose vulnerable/defended pair is a registry
defense profile the manifest must pre-authorize: object-level (BOLA), function-level (BFLA),
property-level mass assignment, workflow and approval bypass, an SSRF-capable upstream fetch, and
unsafe consumption of upstream data. Containment matches Phase 1, plus a PostgreSQL container on
the internal network with no published ports and per-run synthetic credentials, and an internal
upstream so SSRF has somewhere to point.

## Browser adapter

A direct Playwright adapter registered like any other ([ADR 0006](adr/0006-browser-adapter-authorization.md)).
It never selects its own target; it executes a registered flow whose typed steps resolve from the
signed asset in the admitted action. Every navigation, redirect, and subresource origin is
authorized through the runtime target guard before the request happens; an unauthorized origin is
aborted at the routing layer, recorded as a policy denial, and charged to the run budget, never
silently dropped. Fresh context per leg, downloads disabled, fixed viewport/locale/timezone,
animations off, clock frozen. Scored output derives only from application state and typed DOM
assertions. The browser process is killed in the adapter's `finally` path. Per-leg trace ZIP and
screenshots are redacted and referenced by digest in the inventory.

Two drivers share one session protocol. `HtmlFormDriver` renders the fixture's server-side HTML in
process and is bit-exact; the deterministic lane uses it and its replay rate is 1.0.
`PlaywrightDriver` drives pinned Chromium in the container/browser lane and reports its own replay
number separately, because a browser is not bit-reproducible.

## Corpus

Eighteen labelled scenarios span object-, function-, and property-level authorization; role
boundaries; refund and export approval workflows; SSRF; unsafe upstream consumption; and
misconfiguration inventory. Six workflows are authored on both the API and the browser surface
against a shared oracle so cross-surface agreement is measured, not asserted. Every scenario keeps
the Phase 1 shape and is labelled in `scenarios/supportlab/ground-truth.json`; an unlabelled
scenario raises rather than being skipped.

## Metrics and evidence

Each Phase 2 metric ships with a test that fails when the metric is faked: evidence-field
completeness over required per-kind fields, the pre-run resource estimate versus measured use,
cross-surface agreement (disagreements listed per group, never averaged), and per-lane replay
rate (every trial counted). Per-run containment identity comes from the compose project name and a
signed containment prefix; the isolation test asserts no cross-run state leakage across 100 runs.

## Delivery

- `make phase2-check`: lint, format, strict mypy, the full test suite, and the 85% branch floor.
- `make supportlab-demo`: the whole corpus in containers with verified report bundles.
- `PURPLELOOP_CONTAINER_TESTS=1 uv run pytest tests/phase2/test_supportlab_isolation.py`: the
  container containment, egress, database-unreachability, and control-plane authentication checks.
- A separate `phase2` CI workflow with a deterministic `PYTHONHASHSEED` matrix lane and a
  container/browser lane. `phase0.yml` and `phase1.yml` are untouched.
