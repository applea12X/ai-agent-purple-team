# Phase 1 implementation — deterministic closed-loop MVP

The Phase 1 section of [PRD.md](../PRD.md) is authoritative. This document describes the
implemented design and supersedes the earlier work-package draft.

## Contracts and authority

Manifest 1.0 and unversioned actions retain their read-only behavior and canonical hashes.
Manifest 1.1 explicitly grants registered synthetic READ/WRITE operations, credential scopes,
defenses, and graph limits. Destructive actions remain forbidden. Phase 1 manifests contain
opaque credential handles, not plaintext secrets, and bind only loopback HTTP fixture assets.
New optional fields are omitted from legacy canonical serialization.

Scenario 1.1 separates the actor's identity from the explicitly authorized target tenant.
The cross-tenant read exercise is authorized by the harness manifest; its application-level
security verdict is independently determined from the returned object. Legacy scenarios are
converted without inventing missing clean tasks or oracle specifications. Original actions are
retained for explicit migration and execution fails until the required bindings are supplied.

The compiler resolves registered paths from signed asset IDs. It rejects duplicate or cyclic
nodes, missing dependencies, unknown operations, actor/tenant mismatches, and graph limits,
including reserved chat-intent nodes. Execution is sequential in stable topological order.

`SafetyRuntime` remains the per-action boundary. The runner, control plane, HTTP tools, and
chat-generated tool intents share its budgets, kill switch, credential broker, redactor,
registry, and evidence ledger. Control operations consume the run's shared budget. Paired
attack legs have equal limits inside that total budget. Registry schemas and versions are
included in the policy digest; adapter registrations are immutable.

## Fixture and lifecycle

`PurpleTeamRunner` drives admission, provision, seed, clean utility, baseline attack, scoring,
detection, defense selection, reset, defended clean utility, replay, and teardown. Snapshot
hashes verify identical seeded data; the defense configuration is checked separately. A model's
export intent is recorded even when the defended executor denies its side effect.

The deterministic FastAPI target uses synthetic in-memory records, logical ticks, stable IDs,
and a seeded generator. Exact idempotency keys deduplicate successful and denied tool writes;
reusing a key with different arguments is rejected. Control and customer credentials are
separate and are resolved only inside the trusted runtime.

Compose is the default public execution mode. The fixture has a read-only root, tmpfs, a
non-root user, dropped capabilities, no-new-privileges, and only an internal Docker network.
A stateless fixed-destination ingress relay publishes data/control ports on host loopback.
This accommodates Docker engines that do not publish ports for internal-only networks.
The relay has no fixture credentials and accepts no configurable forwarding destination.
The in-process ASGI transport is for fast deterministic tests, not isolation acceptance.

The HTTP adapter authorizes DNS observations before connecting to the selected numeric IP;
there is no second hostname resolution. It disables automatic redirects, charges each hop
against reserved requests, rejects write redirects, bounds headers/body size, and has strict
cancellation and time limits. It intentionally accepts only HTTP and bounded Content-Length
responses because this phase has only the registered local fixture.

Teardown runs in a bounded, shielded cleanup task. Normal teardown uses the safety runtime;
host-owned containment disposal can still destroy the fixture after the kernel is stopped.
Failures preserve partial bundles. Broken evidence is explicitly classified as an integrity
incident and cannot verify as an accepted run.

## Evaluation and artifacts

The corpus has exactly five seeded cases: object ownership, protected-property assignment,
refund approval, direct injection, and indirect injection. Each has a clean task, positive
baseline control, defended negative control, explicit ground truth, versioned mappings, and
one registered defense. Defenses are exact configuration changes, never source patches.

Oracles implement equality, existence, containment, count comparison, and state delta only.
Detectors operate on structured telemetry. Logical detection ticks, susceptibility,
application side effects, harness policy, clean utility, and defended utility are distinct.
Mitigation is credited only after a successful baseline and prevented replay.

Inspect AI is pinned to 0.3.263. Its MemoryDataset, solver, and scorer call the canonical
runner; its registered `purpleloop/offline` model uses exact OfflineModelStore responses.
Fixture, model, and profile misses never fall back to a network provider.

Each scenario bundle contains canonical inputs and plans, snapshots, a hash-chained ledger
and anchor, authorization public key, Inspect JSON log, summary, JUnit, SARIF 2.1.0, offline
HTML, and an artifact inventory. Verification checks the inventory, authorization signature,
canonical input/plan hashes, ledger and normalized replay hash, and evidence references.
The bundled public key supports self-contained integrity checking; external provenance
requires retaining an independently trusted key or inventory digest.

JUnit has one case per scenario: regression=failure, runtime malfunction=error,
inconclusive=skipped. SARIF retains baseline findings even when the paired defense passes.
Same-configuration replay normalization removes operational IDs/timestamps and translates
hash-based evidence links into sequence references; it retains scenario, policy, state,
action, and verdict differences. Vulnerable and defended legs are intentionally different.

## Delivery and acceptance

- `make phase1-check`: lint, format validation, strict mypy, full tests, and coverage floor.
- `make phase1-demo`: five container-backed paired evaluations and verified reports.
- `PURPLELOOP_CONTAINER_TESTS=1 uv run pytest tests/phase1/test_isolation.py --no-cov`:
  explicit containment, egress, authentication, and port checks.
- `purpleloop validate-scenario`, `run-scenario`, and `verify-bundle`: public scenario workflow.

The separate Phase 1 CI workflow adds deterministic and isolated-demo jobs. Phase 0's workflow,
fixture configuration, and command arguments remain unchanged. Measured results belong in
[phase1-acceptance.md](phase1-acceptance.md), not inferred from successful implementation.
