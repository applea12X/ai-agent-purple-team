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
> production adapter, and the browser adapter drives only the bundled synthetic fixture. By
> default, and in every PR lane, all model responses come from offline fixtures. A live model is
> reached only through the opt-in stochastic lane, at an exact model origin that the signed
> manifest grants and that can never coincide with a target asset
> ([ADR 0008](docs/adr/0008-model-plane-separate-from-target-plane.md)).

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

**Real-model knobs (Phase 5).** Decoding, price, and budget are set per run — command line first,
then environment, then the old default (temperature 0, top_p 1, seed 42, 512 output tokens):
`PURPLELOOP_MODEL_{TEMPERATURE,TOP_P,SEED,MAX_OUTPUT_TOKENS}` (`SEED=none` is unseeded),
`PURPLELOOP_MODEL_SEED_POLICY=per-repetition` (repetition *i* signs seed+*i*, so sampled repetitions
differ), `PURPLELOOP_MODEL_COST_BUDGET_MICROUSD` (the signed per-run cap), and
`PURPLELOOP_MODEL_PRICE_{INPUT,OUTPUT}_MICROUSD_PER_1K`. A hosted `openai-compatible` profile
**refuses to run without a price**; a free hosted model needs `--declared-free <model-id>`. Local
profiles (Ollama, vLLM) default to zero. `agent-corpus` runs all 25 scenarios against the pin;
`calibrate-pin` and `calibration-check` fix and check per-pin token expectations
(`baselines/model-calibration/`); `containment-check` holds the compromised-model property over any
run's bundles; `judge-report --judge-endpoint` scores a real judge (`PURPLELOOP_JUDGE_*`) on the
frozen corpus — advisory only. A thinking model's leading `<think>` block is stripped before parsing
and recorded by digest. `make agent-corpus-stochastic` and `make judge-report-networked` wrap these.

**Evaluation matrix (Phase 5, WP5.2).** Models × defenses on the agent corpus, from a signed spec
under `scenarios/matrix/`. `matrix-run` verifies the spec (and, for a spec with a real pin, the
manifest 1.5 authorizing its digest), writes a pre-flight cost and wall-time estimate, and refuses
before the first call when either is over the signed cap; `matrix-report` re-verifies a finished
matrix and recomputes it from its trials. The headline is which defenses still hold when the model
stops cooperating, per scenario — never a per-model score. Advisory; no gate reads it.

```console
make matrix-standins                    # 3 stand-ins x 25 scenarios x 9 columns x 5 reps, offline
uv run purpleloop matrix-run scenarios/matrix/real-pins-subset.json \
  --endpoint http://127.0.0.1:11434/v1 # real pins (local Ollama); see docs/phase5/wp5.2-acceptance.md
```

Phase 4 adds the CI quality system and release machinery: a fast cross-lane smoke demo, five
enforcing gates, signed run attestations, a self-contained audit export, a held-out mutation
set, and a regression registry mapping every accepted finding to its pinning test:

```console
make phase4-check
uv run purpleloop smoke-demo            # 14 scenarios across all three lanes, in process
uv run purpleloop holdout-check         # 17 near-miss mutations; every one must be denied
make pr-check                           # what the PR lane runs, including the five gates
make release-check                      # holdout + attested full-corpus demo + audit export
```

Every complete bundle can carry a signed attestation binding it to the exact code, corpus, and
model pins that produced it, verifiable offline:

```console
uv run purpleloop attest-bundle out/agent-run --commit "$(git rev-parse HEAD)"
uv run purpleloop verify-bundle out/agent-run --attestation
uv run purpleloop audit-export out/agent-run out/audit.json
```

A terminal recording of the one-command demo (`purpleloop smoke-demo`, 14 of 14 passing) followed
by fail-closed cases (an expired manifest refused with `EXPIRED_MANIFEST`, 17 of 17
scope-widening mutations denied by `holdout-check`, and the evaluator-injection report) is in
[docs/demo/phase-demo.cast](docs/demo/phase-demo.cast). Play it with `asciinema play
docs/demo/phase-demo.cast` or load it in
[asciinema-player](https://docs.asciinema.org/manual/player/). It was made by
`scripts/record_demo.py` from commands actually run, and it is not edited.

Fixed sample artifact sets for reviewers — a passing attested run, an admission-denied run,
and a labelled evidence-integrity incident — live in [docs/samples](docs/samples), with the
timed walkthrough protocol in [docs/reviewer-walkthrough.md](docs/reviewer-walkthrough.md).

Building the fixture image pulls `python:3.12-slim` and `ghcr.io/astral-sh/uv` from public
registries, so the first `phase1-demo` needs network access. Evaluation itself is fully offline
and needs no cloud credentials.

## Results so far

Every figure below comes from the acceptance record it cites. The record states how it was
measured and what it does not show. Unless a row says otherwise, the figures describe the
bundled synthetic fixtures and the offline scripted model only. **A passing run is not evidence
that a target or a model is secure.**

| Measure | Result | Source |
| --- | --- | --- |
| Corpus | 48 labelled scenarios: 5 `phase1`, 18 `supportlab`, 25 `agent` | [Phase 3](docs/phase3-acceptance.md) |
| Seeded recall / false positives | 1.0 / 0 in every lane, from explicit ground-truth labels (supportlab: 18 of 18, first written down in the loose-ends audit) | [Phase 1](docs/phase1-acceptance.md), [Phase 3](docs/phase3-acceptance.md), [loose ends](docs/phase5/loose-ends.md) |
| Deterministic replay | 229 of 229 trials matched across the three lanes | [Phase 4](docs/phase4-acceptance.md) |
| Kill switch | p99 0.654 ms over 1,000 trials (cooperative in-process cancellation only) | [Phase 0](docs/phase0-acceptance.md) |
| Smoke demo | 14 of 14 in 12.131 s against a 600 s target (the recorded run) | [WP5.0.11](docs/phase5/wp5.0.11-acceptance.md) |
| Scope-widening holdout | 17 of 17 near-miss mutations denied, base action permitted | [Phase 4](docs/phase4-acceptance.md) |
| Captured model | 0 out-of-scope actions across 25 scenarios with a hostile stand-in model | [Phase 3](docs/phase3-acceptance.md) |
| Evaluator injection | resistance 1.000 (n=24) for the scripted judge; 0.583 with delimiting removed | [Phase 3](docs/phase3-acceptance.md) |
| First real model | `qwen2.5:7b-instruct` (local, temperature 0) on one scenario: the prompt-only defense failed 5 of 5; after enforcing provenance at the email sink it held 5 of 5 | [Phase 4, WP4.0.1](docs/phase4-acceptance.md) |
| Suite | 472 passed, 3 gated skips, 89.40% branch coverage at `ab66ab0` | [WP5.0.1](docs/phase5/wp5.0.1-acceptance.md) |

**Not yet measured:** a real API cost, a real judge, variance under sampling on a real model, the
other 24 agent scenarios on a real model, gates observed failing in CI, precision on a
human-adjudicated sample, and an independent reviewer session.
[docs/phase5/loose-ends.md](docs/phase5/loose-ends.md) lists every such item and who owns it.

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

## Phase 4 architecture

Phase 4 adds the first real-model lanes and the first enforcing CI gates at the same time, and
keeps them apart by construction: **gates read deterministic verdicts only**. Five gate classes
— scope bypass, critical regression, schema drift, budget failure, and a pre-registered
per-risk-class regression test — are pure decision functions that CI and the unit tests share,
each proven to block by a deliberately failing branch (ADR 0013). The nightly lane classifies
every real-model run into a closed outcome vocabulary so an endpoint error is never triaged as
a scenario failure, and reports its own reproduction rate beside — never inside — the
deterministic lanes' replay number. Run attestations (ADR 0012) bind a bundle to the exact
code, corpus, and pins that produced it using the same Ed25519/JCS machinery as the manifest,
with the trust model stated at exactly its real strength. **No number produced only by the
offline stand-in is presented as evidence about a real model**; the acceptance record says
which runs have actually happened.

## Phase 5 governance: shadow mode and risk approval

Before the harness may do more than v1 did, it must first do it in **shadow**: the kernel
admits, compiles, evaluates policy, and reserves budget for every action, then records it as
suppressed and dispatches nothing. A pure `capability_delta` compares a manifest 1.5 against the
signed v1 capability baseline; a non-empty delta is admitted in `execute` mode only under one
signed `RiskApproval` naming exactly that delta and a shadow report of the same surface
([ADR 0014](docs/adr/0014-shadow-mode-and-risk-approval.md),
[WP5.1](docs/phase5/wp5.1-acceptance.md)). The sequence is `purpleloop shadow-run` →
`purpleloop approve` → `purpleloop approval-check`. The committed baseline was signed with an
ephemeral key, and in this single-author project separate keys are not separate people.

## Phase 5 observability (WP5.3)

Telemetry is a projection of the evidence ledger, never a second source of truth: spans and
metrics are computed from redacted, persisted ledger events in the evidence writer, encoded as
OTLP/JSON, and written by default to a local file (`uv run purpleloop observe-suite`). An
optional collector profile (`compose.observability.yaml`) receives them only when a signed
Manifest 1.5 names it. Telemetry is outside the trusted computing base, so a failing sink never
changes an outcome; the failure is recorded in a separate status ledger (ADR 0016). Names are
versioned in [the telemetry namespace](docs/telemetry-namespace.md). `uv run purpleloop analyze`
turns verified bundles into Parquet and queries them with DuckDB, and refuses unverified ones.

## Phase 5 codelab: a fixture that executes code (WP5.5)

`codelab` is a second disposable target: a data-analysis assistant whose "run analysis snippet"
tool executes code in a **sandbox container the fixture owns** (no network, read-only root plus
one 16 MiB tmpfs, every capability dropped, `no-new-privileges`, default seccomp, pids/memory/CPU
limits, a wall-time kill) — never in the fixture's process and never in the harness. Its lane
admits only manifest 1.5, so every run needs a signed approval of its `code-exec` delta.
`purpleloop codelab-run` runs the approval path and the 10-scenario corpus offline against a
stub sandbox; `purpleloop codelab-escape` runs the containment-escape suite against the real
container (hardened runc here; gVisor was not available). See
[ADR 0015](docs/adr/0015-codelab-contained-code-execution.md) and
[WP5.5](docs/phase5/wp5.5-acceptance.md).

## Documentation

- [Product requirements and delivery plan](planning/PRD.md) and the
  [Phase 2](planning/phase2-plan.md), [Phase 3](planning/phase3-plan.md),
  [Phase 4](planning/phase4-plan.md), [Phase 5](planning/phase5-plan.md), and
  [Phase 6](planning/phase6-agents-plan.md) plans
- [Architecture](docs/architecture.md) and [threat model](docs/threat-model.md)
- [Rules of engagement](docs/rules-of-engagement.md)
- Designs: [Phase 1](docs/phase1-plan.md), [Phase 2](docs/phase2-plan.md),
  [Phase 3](docs/phase3-plan.md), [Phase 4](docs/phase4-plan.md), and the
  [evaluation methodology](docs/evaluation-methodology.md)
- Acceptance records: [Phase 0](docs/phase0-acceptance.md), [Phase 1](docs/phase1-acceptance.md),
  [Phase 2](docs/phase2-acceptance.md), [Phase 3](docs/phase3-acceptance.md),
  [Phase 4](docs/phase4-acceptance.md), and the Phase 5 work-package notes in
  [docs/phase5](docs/phase5), including the [loose-ends audit](docs/phase5/loose-ends.md)
- Operations: [retention policy](docs/retention-policy.md),
  [incident runbook](docs/incident-runbook.md),
  [reviewer walkthrough](docs/reviewer-walkthrough.md), and the
  [gate baselines](baselines/README.md)
- Decision records in [docs/adr](docs/adr)
