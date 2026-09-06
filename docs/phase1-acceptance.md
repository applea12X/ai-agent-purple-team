# Phase 1 Acceptance Record

Date: September 6, 2026

Measured on a local macOS development environment with Docker Desktop. Every number below was
observed from a command run, not inferred from a successful implementation. Results describe the
five synthetic fixtures at their recorded versions and seeds; they are not claims about real
models or production applications.

## Quality gate

Command:

`make phase1-check`

Result:

- Ruff lint and format checks passed.
- mypy strict mode passed for 42 source files.
- 133 tests passed, 1 skipped.
- Branch-aware coverage: 88.47% (required: 85%).
- The full suite was also run under `PYTHONHASHSEED` 0, 1, 2, 3, and 5; all five runs passed
  133 tests. See "Defect found and fixed during acceptance".

The single skip is `test_container_denies_egress_and_cross_plane_credentials`, which is gated
behind `PURPLELOOP_CONTAINER_TESTS=1` and reported separately below.

## Phase 0 regression

Command:

`uv run pytest tests/unit tests/contract tests/property tests/integration tests/acceptance tests/fault_injection --no-cov`

Result:

- 57 passed — the full Phase 0 suite at commit `17dd1bf`, unchanged.

Manifest 1.0 and unversioned actions keep their read-only behavior, denial reasons, signature
inputs, and canonical hashes. Phase 1's optional fields are omitted from legacy canonical
serialization, so Phase 0 ledgers and manifests remain readable and verifiable.

## Deterministic replay

Command:

`uv run pytest tests/phase1/test_loop.py::test_same_configuration_replay_100_trials`

Method:

- 20 complete paired evaluations per scenario across all five scenarios (100 trials).
- Each trial's normalized event and oracle hashes are compared with that scenario's first trial.
- All trials are counted; no trial or scenario is excluded.

Result:

- 100/100 matching normalized event and oracle hashes (required: at least 95).
- 0 mismatches.

The measured record is written to `artifacts/phase1-acceptance.json` on each run.

## Seeded-finding recall and false positives

Method:

Recall and false positives are computed by `corpus_metrics` from the explicit labels in
`scenarios/phase1/ground-truth.json`, not from scenario-level pass/fail. Four labelled controls
per scenario provide 20 positive controls and 20 defended negative controls. An unlabelled
scenario raises rather than being skipped, and labelled scenarios that were never executed are
reported in `unevaluated_scenarios`.

Result:

- Seeded recall: 1.0 — 20 true positives, 0 false negatives, all five seeded cases detected
  (required: at least 90%).
- False positives: 0 across 20 defended negative-control executions, rate 0.0
  (required: at most 5%, and at most one reviewed false positive).
- `unevaluated_scenarios` and `missing_negative_controls` were both empty.

The metric itself is unit-tested against injected failures in `tests/phase1/test_ground_truth.py`:
a suppressed finding lowers recall to 0.8, and a security finding in a defended negative control
is counted as a false positive. Without those tests a metric that always returned 1.0 would pass.

## Container isolation

Command:

`PURPLELOOP_CONTAINER_TESTS=1 uv run pytest tests/phase1/test_isolation.py --no-cov`

Result — 2 passed:

- Compose contract: read-only root, tmpfs state, all capabilities dropped,
  `no-new-privileges`, internal-only network, loopback-bound relay ports, no relay environment.
- Live container: non-root user, unwritable root filesystem, outbound connection to `1.1.1.1:443`
  refused, and a customer credential presented to `/control/snapshot` rejected with HTTP 403
  while the control credential succeeds through the loopback relay.

The fixture stays on an internal-only Docker network. A stateless fixed-destination ingress relay
publishes the data and control ports on host loopback, because this Docker engine does not publish
ports for internal-only networks. The relay holds no fixture credentials and accepts no
configurable forwarding destination.

## Offline demo

Command:

`make phase1-demo`

Result:

- Five container-backed paired evaluations: `bola`, `mass-assignment`, `refund`,
  `direct-injection`, and `indirect-injection` — all passed, in nine of eleven runs. The two
  exceptions failed during fixture image build, before any evaluation; see Known limits.
- Bundle verification succeeded for the suite and every scenario directory.
- Teardown removed all `phase1` containers and the isolated network; `docker ps -a` listed none.
- No cloud credentials and no network model provider were used; all model responses came from
  `OfflineModelStore`, and a fixture miss fails closed.

## Side effects, failure, and cancellation

- The integration suite observed zero unauthorized harness side effects: every paired replay leg
  recorded `unauthorized_side_effects == 0`.
- Mutations of host, tenant, resource, method, arguments, credential handle, and side-effect class
  are denied at the policy boundary before any adapter I/O, property-tested over the compiled
  attack action. Redirect mutations outside signed scope are denied by the Phase 0 property suite.
- Substituting a signed tenant that does not own the target resource is denied even though both
  tenants are in signed scope; that case additionally asserts no fixture audit entry was written
  and no request budget was consumed.
- A signed manifest may authorize the harness to exercise a synthetic fixture operation while the
  state oracle independently classifies the application's response as an authorization failure.
  A permitted harness action is never, by itself, evidence that an attack failed.
- Failure and cancellation were injected at all 12 lifecycle stages, in both raising and cancelled
  forms. Every case tore the fixture down, appended a termination outcome when the ledger was
  writable, and left either a verifiable partial bundle or an explicit evidence-integrity incident.
- A deliberately broken ledger produces `integrity-incident.json` and cannot verify as an accepted
  run.

## Defect found and fixed during acceptance

Acceptance runs failed intermittently — 26 tests, roughly three runs in eight — with
`cryptography.exceptions.InvalidSignature` while verifying a bundle's manifest.

Root cause: `frozenset` fields serialize to JSON arrays, and JCS (RFC 8785) sorts object keys but
preserves array order. Canonical bytes therefore depended on set iteration order, which varies with
`PYTHONHASHSEED` and with how a set was built. A manifest signed before being written to a bundle
could fail verification after being read back, and two processes could compute different digests
for identical content. This affected every canonical digest and signature, including Phase 0's.

Fix: `order_sets` in `src/purpleloop/schemas/common.py` walks a python-mode dump alongside the
json-mode dump and sorts only the arrays that came from sets, leaving ordered tuples untouched.

Verification:

- `tests/unit/test_canonicalization.py` covers JSON round-trip signature and digest stability, a
  pinned expected digest, insertion-order independence, and non-reordering of ordered tuples.
  Reverting the fix fails 3 of those 4 tests on every seed tried.
- `PYTHONHASHSEED` 1, 2, and 3 each previously failed 26 Phase 1 tests and now pass; reverting the
  fix reproduces exactly 26 failures on each.
- With the fix, one pinned manifest produced an identical digest across eight hash seeds.

## Known limits

- `src/purpleloop/fixture/relay.py` shows 0% coverage in the deterministic lane. It is host-side
  ingress plumbing that only executes inside the container lane, where it is exercised by both the
  isolation test and `make phase1-demo`. It is not covered by the branch-coverage figure above.
- `make phase1-demo` is offline for evaluation but not for image build. `docker compose up --build`
  resolves `python:3.12-slim` and `ghcr.io/astral-sh/uv:0.11.7` from public registries, so the
  first build — and any rebuild whose layers are not cached — needs registry network access. Two
  of eleven demo runs on this machine failed there with
  `lookup ghcr.io: no such host`, a transient local DNS failure. No cloud credentials are involved
  and no evaluation had started. Both failures were handled fail-closed: the run reported
  `partial evidence: <path>`, retained the partial bundle, and tore the fixture down. The other
  nine runs completed all five scenarios and verified their reports.
- Detection delay uses injected logical ticks and is not a claim about production wall-clock
  latency. Budget tokens are reserved capacity, not cloud billing.
- Finding reproducibility is not asserted from a single paired run.
