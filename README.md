# PurpleLoop

PurpleLoop is a local-first safety kernel for explicitly authorized purple-team evaluations of
SaaS and agentic applications. Phase 0 is the read-only single-action kernel: it proves
authorization, scope, budget, cancellation, evidence, credential, and deterministic-replay
controls. Phase 1 builds a deterministic closed-loop evaluation on top of that kernel:

`provision → seed → clean task → baseline attack → score → detect → select defense → reset → replay → teardown`

> **Safety warning:** Use PurpleLoop only against its bundled disposable fixtures or an exact
> asset covered by a current, signed authorization manifest. Writes are permitted only for exact
> registered synthetic fixture operations that a 1.1 manifest explicitly grants. Destructive
> actions, unknown operations, and targets outside signed scope are always denied. There is no
> production or live-model adapter, and the browser adapter drives only the bundled
> synthetic fixture; all model responses come from offline fixtures.

## Setup and verification

Requirements: Python 3.12, `uv`, and Docker for the fixture and container lanes.

```console
uv sync --frozen
make phase0-check
make phase1-check
```

`phase0-check` and `phase1-check` both run Ruff, formatting validation, strict mypy, pytest, and
the branch-coverage floor over the whole suite, including the 1,000-trial kill-switch
measurement, deterministic replay checks, and fail-closed tests.

```console
make phase0-full-check
make phase1-demo
PURPLELOOP_CONTAINER_TESTS=1 uv run pytest tests/phase1/test_isolation.py --no-cov
```

`phase0-full-check` builds and verifies the isolated Phase 0 Compose fixture, then tears it down.
`phase1-demo` is the single offline entry point: it provisions the Phase 1 fixture, runs all five
scenarios, writes and verifies their report bundles, and tears the fixture down even when the run
fails. The container lane asserts containment, blocked egress, and control-plane authentication.

Phase 2 adds `supportlab`, a persistent multi-organization SaaS fixture backed by PostgreSQL, and
a browser surface driven by Playwright:

```console
make phase2-check
make supportlab-demo
PURPLELOOP_CONTAINER_TESTS=1 uv run pytest tests/phase2/test_supportlab_isolation.py --no-cov
uv run purpleloop supportlab-run scenarios/supportlab/bola-ticket.yaml out/bola --fixture in-process
```

`supportlab-demo` runs the eighteen-scenario corpus in containers on PostgreSQL, drives the browser
scenarios through Chromium, writes and verifies every report bundle, and tears the stack down even
on failure. The deterministic lane runs the same corpus in process against SQLite with an exact
HTML driver; the two engines produce byte-identical seed hashes.

Phase 3 adds an LLM/RAG agent surface, a separate model plane, an adaptive attacker, and a
hybrid judge — all offline by default:

```console
make phase3-check
make agent-demo
make judge-report
uv run purpleloop agent-run scenarios/agent/agent-indirect-ticket.yaml out/agent \
  --repetitions 5 --judge --attacker
```

`agent-demo` runs the twenty-five agent scenarios through the Inspect bridge, writes one verifiable
bundle per repetition, and verifies the suite. It authorizes **no** model endpoint at all, so it
cannot reach one. The stochastic lane is opt-in (`make agent-stochastic` with
`PURPLELOOP_MODEL_ENDPOINT`, and `PURPLELOOP_MODEL_API_KEY` for a hosted API); a missing credential
is a recorded skip and never a silent fall back to the offline provider.

Building the fixture image pulls `python:3.12-slim` and `ghcr.io/astral-sh/uv` from public
registries, so the first `phase1-demo` needs network access. Evaluation itself is fully offline
and needs no cloud credentials.

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
uv run purpleloop validate-scenario scenarios/phase1/bola.yaml
uv run purpleloop run-scenario scenarios/phase1/bola.yaml manifest.json public.pem out/bola \
  --key-id engagement-key
uv run purpleloop verify-bundle artifacts/phase1-demo/<run>/bola
uv run purpleloop agent-run scenarios/agent/agent-indirect-ticket.yaml out/agent --judge
uv run purpleloop judge-report --output-dir artifacts/judge
```

The CLI never turns an offline-fixture miss into a network request.

## Phase 0 architecture

The signed manifest and trusted tool registry admit a typed read request. A trusted adapter
reports DNS and every redirect hop to the target guard before I/O. The guard rechecks
authorization, revocation, policy freshness, exact scope, exclusions, tool/path binding, egress,
and IP allowlists. Budget and kill-switch controls own the complete adapter lifecycle. Results
are redacted before entering the hash-chained evidence ledger.

## Phase 1 architecture

`SafetyRuntime` remains the per-action enforcement boundary. `PurpleTeamRunner` drives the
lifecycle above and submits every target-facing action — including tool intents produced by chat
output — through that same boundary, sharing one budget ledger, kill switch, credential broker,
redactor, adapter registry, and evidence ledger per run.

Scenario steps compile into a typed DAG before provisioning; planner output is untrusted data and
cannot contain code, shell, URLs, or browser instructions. The fixture runs in a container with a
read-only root, tmpfs state, dropped capabilities, `no-new-privileges`, and an internal-only
network, with a separately scoped control plane that attack credentials cannot address. Oracles
use a closed operator set, defenses come from a versioned registry that the manifest must
pre-authorize, and a defense is credited only when the seeded attack succeeds in the baseline and
fails on replay under the same seed, plan, and budget.

Harness authorization and target vulnerability are independent facts: a permitted harness action
is never, by itself, evidence that an attack failed.

## Phase 2 architecture

`supportlab` is a persistent, multi-organization SaaS target with six toggleable flaw classes,
each paired to a registry defense the signed manifest must pre-authorize. Resource ownership is
resolved from the signed manifest, never from the fixture under test, so harness authorization and
target vulnerability stay independent even across a database of seeded rows. A `LaneContract`
parameterizes the one runner over both fixtures. The browser is a first-class adapter under the
same authority as HTTP and tool adapters: it never selects its own target, every navigation and
subresource origin is authorized before the request, and scored output comes only from application
state and typed DOM assertions. Determinism under a real database rests on total query ordering,
seed-derived identifiers, a banned-nondeterministic-function rule, and a snapshot hash over a
canonical ordered read; the API lane reports bit-exact replay and the browser lane reports its own
number separately.

## Phase 3 architecture

Phase 3 introduces the project's first non-deterministic components, so it introduces a contract to
go with them: **deterministic oracles remain binding, stochastic components are advisory, and every
verdict records which kind produced it.** That is a required `VerdictProvenance` field on every
scored artifact and a single `require_binding()` check at all three gates — run status, mitigation
credit, and the corpus metric — not a statement of intent. No stochastic result gates a
release-blocking invariant.

The model lives on a **separate plane** from the target. The fixture keeps its Phase 2 no-egress
posture unchanged; a model endpoint is an exact signed origin that the schema forbids from
coinciding with any target asset, and it is deliberately not plan-addressable, so no compiled action
can aim at it. An offline engagement authorizes no model endpoint at all.

`supportlab` gains a RAG assistant with provenance-tagged retrieval, a memory store, and narrow
email, CRM, refund, export, and memory tools. The assistant parses intents; it never invokes a tool.
Each intent is validated against its typed argument model, compiled, and executed one at a time
through `SafetyRuntime`, capped by the signed per-turn limit — and every refusal is recorded as
evidence about what the model tried. Retrieval is exact and totally ordered with no embeddings, so
*what the assistant was shown* stays reproducible even where *what it said* would not be.

The judge runs only where a deterministic oracle abstained. Its input is typed, bounded, and
delimited; its citations are validated against what was supplied; abstention is a first-class
outcome; and its verdict is advisory by construction.

## Documentation

- [Product requirements and delivery plan](planning/PRD.md) and the
  [Phase 2](planning/phase2-plan.md) and [Phase 3](planning/phase3-plan.md) plans
- [Architecture](docs/architecture.md) and [threat model](docs/threat-model.md)
- [Rules of engagement](docs/rules-of-engagement.md)
- Designs: [Phase 1](docs/phase1-plan.md), [Phase 2](docs/phase2-plan.md),
  [Phase 3](docs/phase3-plan.md), and the
  [evaluation methodology](docs/evaluation-methodology.md)
- Acceptance records: [Phase 0](docs/phase0-acceptance.md), [Phase 1](docs/phase1-acceptance.md),
  [Phase 2](docs/phase2-acceptance.md), and [Phase 3](docs/phase3-acceptance.md)
- Decision records in [docs/adr](docs/adr)
