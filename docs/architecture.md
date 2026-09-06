# Architecture

## Phase 0 — single-action kernel

### Trust boundaries

The authorization verifier, tool registry, target guard, policy engine, budget ledger, kill
switch, credential broker, trusted adapters, redactor, and evidence writer form the Phase 0
trusted computing base. Action requests, model fixtures, target content, URLs, and adapter
results are untrusted data.

### Fail-closed flow

1. Verify the canonical Ed25519 signature, UTC validity window, and available revocation status.
2. Match the action to an authorized adapter and operation, then to a trusted tool definition.
3. Canonicalize the URL and enforce its method, resource path, tenant, asset, egress, and exact
   exclusions.
4. Atomically reserve budget and spawn all adapter activity under kill-switch ownership.
5. Before the initial connection and every redirect, accept only a trusted `TargetObservation`
   with a consecutive hop number and at least one resolved address.
6. Reverify the manifest and policy, bind the observed URL to the same asset/tool/resource, and
   require every address to be explicitly allowlisted.
7. Redact target and credential secrets, append evidence atomically, and finalize the reservation.

Automatic redirect following is forbidden for future network adapters. They must resolve and
authorize each hop before connecting.

### Evidence and replay

Each evidence record contains an exact hash over its full canonical content and its parent hash.
The colocated anchor detects accidental or unsynchronized tail truncation but is not an external
signature. A separate semantic replay hash excludes timestamps, run/trace IDs, parent/event
hashes, and measured latency. The score hash covers the deterministic status, reason, and
redacted result. Exact evidence hashes and semantic replay hashes serve different purposes.

### Lifecycle guarantees

`KillSwitch.spawn` checks state and creates/registers work under one lock. Termination changes
state, cancels all owned tasks, and waits for their cancellation. The runtime applies the
remaining engagement wall-time as an execution deadline. Reservations are single-use and cannot
refund more than they reserved.

## Phase 1 — deterministic closed loop

### Orchestration

`SafetyRuntime` stays the trusted per-action boundary. `PurpleTeamRunner` coordinates
`provision → seed → clean task → baseline attack → score → detect → select defense → reset →
replay → teardown`, and submits every target-facing action through that boundary. One run shares
a budget ledger, kill switch, credential broker, redactor, adapter registry, and evidence ledger,
so control-plane calls and paired attack legs draw on the same totals.

Scenario steps compile into a typed DAG before provisioning. The compiler rejects duplicate node
IDs, cycles, unknown adapters or operations, dangling dependencies, actor/tenant mismatches, and
plans over the manifest's node or depth limits. Planner output is untrusted data: it carries no
code, shell, URL, or browser fields. Execution is sequential in stable topological order.

The adapter registry is keyed by exact adapter and operation names, is immutable after admission,
and fails startup on duplicate keys. An adapter can neither select another adapter nor execute
outside the safety runtime.

### Fixture and drivers

The Phase 1 fixture is separate from the Phase 0 one rather than a relaxation of it. It runs with
a read-only root, tmpfs state, dropped capabilities, `no-new-privileges`, loopback-bound ports,
and no external egress. Its control plane — provision, seed, snapshot, telemetry, defense, reset,
teardown — is separately scoped, and attack credentials cannot address it. Seed and reset return
canonical state hashes the runner verifies before each paired leg.

Determinism comes from a seeded generator, an injected logical clock, stable identifiers, and
ordered responses; no wall-clock or random value reaches scored output. The chat adapter is backed
only by exact `OfflineModelStore` responses and never invokes tools itself: a model-produced tool
intent is parsed as untrusted data, compiled into a typed action, and sent through the runtime.
The fixture controller's `finally` path always requests teardown, records the outcome, flushes
evidence, and preserves partial artifacts.

### Scoring and canonical artifacts

Oracles use a closed operator set — equality, existence, containment, count comparison, and
before/after delta — over typed paths; no expressions are evaluated. Clean utility is scored
before the attack and again after mitigation, and attack susceptibility is recorded separately
from executed unauthorized side effects. Defenses come from a versioned registry that the signed
manifest must pre-authorize; Phase 1 never edits application source.

Canonical objects carry stable schema versions and SHA-256 digests. Because JCS sorts object keys
but preserves array order, set-derived arrays are sorted before canonicalization so digests and
signatures never depend on iteration order. Each run emits a self-contained bundle — normalized
inputs, compiled plans, ledger and anchor, paired snapshots, Inspect logs, canonical JSON, JUnit,
SARIF, HTML, and a digest inventory — and verification rechecks every digest, ledger link,
required artifact, and referenced evidence ID.
