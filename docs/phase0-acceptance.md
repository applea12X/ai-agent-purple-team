# Phase 0 Acceptance Record

Date: July 25, 2026

## Quality gate

Command:

`uv sync --frozen && make phase0-check`

Result:

- Ruff lint and format checks passed.
- mypy strict mode passed for 25 source files.
- 57 tests passed.
- Branch-aware coverage: 87.00% (required: 85%).

The suite covers strict schemas, signature/time/dynamic-revocation checks, policy outage and
staleness, exact exclusions, trusted DNS and redirect observations, resource/path/tool binding,
hard wall time, atomic single-use budgets, automatic credential redaction, active cancellation,
concurrent evidence appends, offline-model fixture misses, semantic event/score replay, CLI
success/failure paths, and denied-action non-invocation.

## Kill-switch latency

Method:

- 1,000 independent asyncio trials.
- Each trial registered a cancellable 30-second task, triggered termination, yielded to the event loop, and measured elapsed monotonic time.
- Machine: local macOS development environment.

Result:

- p99: 0.654 ms.
- required p99: no more than 2,000 ms.

Every measured trial waited until adapter activity had started; pre-start denials were not
counted. This measures Phase 0 cooperative in-process cancellation only, not an uncontrolled
remote process.

## Fixture isolation

Commands:

`make fixture-up && make fixture-check && make fixture-down`

Result:

- Image built successfully.
- Container became healthy.
- `/health` and synthetic `/records/record-1` reads succeeded.
- Container ran as an unprivileged user with all capabilities dropped, a read-only filesystem, `no-new-privileges`, and an internal-only network.
- Teardown removed the container and isolated network.

## Evidence and secret handling

- Tests confirm configured canary, dynamically resolved credential, bearer-header, and
  exception-contained values do not appear in returned runtime results or evidence events.
- Ledger verification detects content mutation, partial writes, tail truncation, broken ordering, and invalid parent/event hashes.
- Runs with different timestamps, run/trace IDs, and latency produce the same semantic event and
  deterministic score hashes when their meaningful outcomes are equal.
- The ledger is described as tamper-evident, not immutable.
