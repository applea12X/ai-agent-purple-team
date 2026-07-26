# PurpleLoop

PurpleLoop is a local-first safety kernel for explicitly authorized purple-team evaluations of
SaaS and agentic applications. Phase 0 is deliberately read-only: it proves authorization,
scope, budget, cancellation, evidence, credential, and deterministic-replay controls before
later phases add real attack execution.

> **Safety warning:** Use PurpleLoop only against disposable fixtures or assets covered by an
> exact, current, signed authorization manifest. Phase 0 has no production HTTP, browser,
> write, or live-model adapter.

## Setup and verification

Requirements: Python 3.12, `uv`, and Docker for the optional fixture smoke test.

```console
uv sync --frozen
make phase0-check
make phase0-full-check
```

`phase0-check` runs Ruff, formatting validation, strict mypy, pytest, branch coverage, the
1,000-trial active kill-switch measurement, deterministic replay checks, and adversarial
fail-closed tests. `phase0-full-check` additionally builds and verifies the isolated Compose
fixture, then tears it down.

## CLI

```console
uv run purpleloop --help
uv run purpleloop validate-manifest manifest.json public.pem --key-id engagement-key
uv run purpleloop check-action manifest.json action.json public.pem --key-id engagement-key
uv run purpleloop run-mock manifest.json action.json public.pem evidence.jsonl \
  --key-id engagement-key
uv run purpleloop verify-ledger evidence.jsonl
uv run purpleloop offline-complete tests/fixtures/model_responses/phase0.json request.json \
  --model offline-model --profile deterministic
```

The CLI never turns an offline-fixture miss into a network request.

## Phase 0 architecture

The signed manifest and trusted tool registry admit a typed read request. A trusted adapter
reports DNS and every redirect hop to the target guard before I/O. The guard rechecks
authorization, revocation, policy freshness, exact scope, exclusions, tool/path binding, egress,
and IP allowlists. Budget and kill-switch controls own the complete adapter lifecycle. Results
are redacted before entering the hash-chained evidence ledger.

See [architecture](docs/architecture.md), [threat model](docs/threat-model.md),
[rules of engagement](docs/rules-of-engagement.md), and the
[Phase 0 acceptance record](docs/phase0-acceptance.md).
