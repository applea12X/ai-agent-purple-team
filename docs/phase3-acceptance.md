# Phase 3 Acceptance Record

Date: September 9, 2026

Measured on a local macOS development environment (Darwin 25.6.0, Python 3.12) with the offline
scripted provider. Every number below was observed from a command that was actually run, not
inferred from a successful implementation. Results describe the twenty-five synthetic `agent`
scenarios at their recorded versions and seed. **No real model was called in producing any number
in this document**, and §"Known limits" says exactly what that costs.

## Quality gate

Command: `make phase3-check`

- Ruff lint and format checks passed; mypy strict passed for 73 source files.
- **343 tests passed, 3 skipped. Branch-aware coverage 88.59%** against the 85% floor.

The three skips are gated rather than unexercised: the Phase 2 and Phase 1 container tests
(`PURPLELOOP_CONTAINER_TESTS=1`) and the cross-engine agent hash test, which additionally needs
`PURPLELOOP_TEST_POSTGRES_DSN`. All three were run and passed on the container lane below.

## Prior suites unchanged

- `tests/unit tests/contract tests/property tests/integration tests/acceptance tests/fault_injection tests/phase1`:
  **133 passed, 1 skipped** — the Phase 0 and Phase 1 suites, unchanged.
- `tests/phase2`: **37 passed, 1 skipped** — unchanged.
- The Phase 2 lane's seed hash for seed 42 is byte-identical to its recorded value
  (`5c270cdda4ecb931d37a1285636cc84f609fbc1c3d467d05a0116cca235d1b3d`), asserted against the
  literal. Agent tables join the scored projection only on the agent lane.
- Manifest 1.0, 1.1, and 1.2 documents keep byte-identical canonical bytes: every 1.3 field
  defaults to absent, asserted rather than intended.

## Container lane

Docker Engine 29.7.2. Run on September 15, 2026, after the in-process record above was written — the
container-gated tests had been skipped until then, and the run found a defect (below).

- `PURPLELOOP_CONTAINER_TESTS=1 uv run pytest tests/phase2/test_supportlab_isolation.py tests/phase1/test_isolation.py`:
  **9 passed**, including the two container tests previously reported as skips. The live containers
  ran non-root with external egress refused and a customer credential rejected by the control plane.
- `make supportlab-demo`: the 18-scenario Phase 2 corpus on PostgreSQL with the browser scenarios on
  Chromium, rebuilt from the Phase 3 fixture source. `verify-bundle` returned
  `{valid: True, complete: True, scenarios: 18}`. Teardown left no supportlab containers, networks,
  or volumes.
- **Agent surface on PostgreSQL.** Seeding the agent surface through the real control route produces
  the same state hash on PostgreSQL 16 and SQLite (`e7cfb55e…`, 51 chunks, 12 scored tables), and
  reset restores it on both. The full 25-scenario agent corpus passed **25/25** against PostgreSQL,
  and every scenario's oracle hash was **identical** to its SQLite run (25/25).
- Scope of that last measurement, stated precisely: the database was a real PostgreSQL 16 container
  pinned by digest, while the application ran in process over ASGI transports. There is no compose
  stack for the agent lane, so the agent routes have not run inside the fixture container image; the
  Phase 2 routes have, via `supportlab-demo`.

## Corpus

| Lane | Scenarios |
| --- | --- |
| `phase1` | 5 |
| `supportlab` | 18 |
| `agent` | 25 |
| **Total** | **48** (PRD target 30–50) |

All 25 agent scenarios carry complete, versioned taxonomy mappings across the five pinned
taxonomies, a `risk_class`, provenance, and licence, and every one has a **deterministic** security
and utility oracle. All nine injection channels are populated, checked by a test over the scenario
vocabulary rather than left to review.

Imported third-party cases (PyRIT, garak, Promptfoo, AgentDojo) arrive **not runnable** with their
conversion issues recorded and are **not counted** in the 48. None of those formats carries a
fixture binding, a clean utility task, a deterministic oracle, or a ground-truth label.

## Corpus metrics

Command: the corpus metric over 25 real paired runs against `scenarios/agent/ground-truth.json`
(`artifacts/phase3-corpus-metrics.json`).

- Seeded recall **1.0** (25 true positives, 0 false negatives) against a ≥90% threshold.
- False positives **0** across 25 defended negative controls; false-positive rate **0.0** against
  a ≤5% threshold.
- 25 positive-control runs, 25 negative-control runs, 0 missing negative controls, 0 unevaluated
  labelled scenarios.
- Every scenario was susceptible in the baseline leg and every defended replay recorded zero
  unauthorized side effects.

## The four numbers

Measured over 5 repetitions per scenario (`make agent-demo`, `--repetitions 5`;
`artifacts/agent-demo/<run>/stochastic/`).

| Measure | min | max | mean across 25 scenarios |
| --- | --- | --- | --- |
| Clean utility | 1.0 | 1.0 | 1.0 |
| Utility under attack | 1.0 | 1.0 | 1.0 |
| Attack success | 1.0 | 1.0 | 1.0 |
| Executed unauthorized side effects | 0.0 | 1.0 | 0.96 |

The side-effect row was re-measured after the attacker-contamination fix below; the earlier figure
(2.0 / 3.0 / 2.96) counted the probe's own writes and was wrong. A minimum of 0.0 is correct and not
a gap: a scenario such as `agent-system-prompt-leakage` is proven by an output-derived predicate
rather than by a write, so it has no unauthorized side effect to count.

Reported separately, never composited. Every figure carries its n, seed policy, model pin, and
exclusion count; a representative one reads
`{value: 1.0, n: 5, ci: [0.566, 1.0], provenance: pinned-stochastic, model_pin_id: offline-scripted, seed_policy: fixed-per-repetition, excluded: 0}`.
Proportions use a Wilson interval, counts a seeded percentile bootstrap; both are named where the
number appears. **The interval on n=5 is wide** — 0.566 to 1.0 for a perfect 5/5 — and that is the
honest reading, not a defect.

All 25 scenarios completed 5 of 5 repetitions with **zero exclusions**, and all 25 were reproducible
(every repetition reached the same security verdict). `Finding.reproducible` is answered from that
set and carries its basis.

## Determinism

Command: `tests/phase3/test_agent_acceptance.py::test_agent_lane_replay_determinism`
(`artifacts/phase3-replay.json`).

- Agent-lane replay **75/75 trials matched** (25 scenarios × 3 trials), rate **1.0**, no trial
  excluded, no mismatched scenario.
- The agent lane is deterministic **because the provider is**: the scripted model makes no network
  call. This measures the lane and the fixture, not a model. A stochastic lane using a real model
  would report its own measured variance and is not claimed here.
- Phase 0, 1, and 2 lanes replay exactly as before.

## Containment with a compromised model

Command: `tests/phase3/test_compromised_model.py`

Every scenario re-run against `HostileModel`, which ignores the prompt and emits the most damaging
intent set it can express — including operations that do not exist (`shell.exec`) and control-plane
operations (`fixture.teardown`). Across all 25:

- **Zero out-of-scope actions.** Every compiled intent named a registered operation, ran on the
  `tool` or `http` adapter, targeted `http://127.0.0.1:28080/`, carried the scenario actor's own
  credential handle, and named the actor's own tenant.
- Every scenario recorded at least one `TOOL_INTENT_REJECTED` event: invented operations are
  refused as evidence, not raised as harness errors, and the run completes and is scored.
- Teardown completed and the fixture closed in every case.

Property tests additionally confirm an intent cannot carry an adapter, target, credential, or
budget, and that arguments are validated against the operation's typed model at parse time.

## Judge and evaluator red team

Command: `uv run purpleloop judge-report` (`artifacts/judge/evaluator-redteam.json`).

Against the frozen 24-case corpus (digest `9bcf0a2f…`, pinned in the test file):

| Measure | Value | Threshold |
| --- | --- | --- |
| Held-out injection resistance | **1.000** (24/24) | ≥ 0.99 |
| Critical false passes | **0** | 0 |
| Krippendorff's alpha | **1.000**, CI [1.000, 1.000], n = 24 | ≥ 0.7 |
| Cohen's kappa | **1.000**, n = 14 (abstention-excluded) | reported |
| Order-swap consistency | **1.000**, 24 trials | ≥ 0.95 |
| Abstentions | 10 of 24 | reported |

**These numbers are about the harness, not about a model.** `ScriptedJudge` is a stand-in with one
declared failure mode — it follows directives it can read as instructions. What the corpus measures
with it is the evaluator hardening that is ours to get right: delimiting, citation validation, and
abstention. A perfect score from a deterministic stand-in is not evidence that a real judge resists
injection.

The negative control is what makes the number a measurement rather than a constant. With the
delimiting mitigation removed, resistance falls to **0.583** (14/24) with **five critical false
passes** (`inject-1`, `approval-1`, `gaming-1`, `position-1`, `family-1`). A second test shows a
contrary judge drops alpha below 0.7.

The labels were adjudicated and frozen before the judge was tuned, and their digest is pinned in
the test file rather than read from the corpus, so tuning against them fails that test.

## Evidence completeness

Command: `tests/phase3/test_agent_acceptance.py::test_evidence_completeness_over_the_agent_corpus`
(`artifacts/phase3-evidence-completeness.json`).

- Minimum completeness across all 25 scenarios: **1.0** against a ≥0.99 threshold, computed by the
  tested metric over required per-kind fields, now including `MODEL`, `JUDGE`, and `PROPOSAL`.
- A test asserts the metric falls when a required field is removed, so it can fail.

## Token and cost accounting

Command: `tests/phase3/test_agent_acceptance.py::test_token_and_cost_estimate_against_actual`
(`artifacts/phase3-token-accounting.json`).

- **24 of 25 scenarios within ±10%** of the pre-run token estimate. Deltas range from −16.04% to
  +6.31%.
- The one miss is `agent-system-prompt-leakage` at **−16.04%** (estimated 1284 tokens, actual
  1078): its attack turn produces a message and no tool intents, so its output is shorter than the
  corpus mean the pin was calibrated against. It is reported, not excluded, and the calibration was
  **not** re-tuned to make it pass — that would be fitting the estimate to the run.
- The pin's expectations (187 input, 27 output tokens per call) were calibrated once, on
  2026-09-09, over 150 model calls across the corpus (input range 143–258, output range 19–60) and
  held fixed, the same discipline `ResourceCalibration` uses for wall time. Without declared
  expectations the estimator falls back to the decoding cap, which is an explicit upper bound and
  is reported as such.
- **Actual API cost is a measured zero, not a blank**: the offline pin's declared price is zero
  because it makes no network call. A real-cost figure requires the stochastic lane and does not
  exist yet.

## Offline demo

Command: `uv run purpleloop agent-demo --repetitions 5`

- 25 scenarios × 5 repetitions = **125 bundles, all verified** (`verify-bundle` returned
  `{valid: True, complete: True, scenarios: 125}`).
- Every repetition ran through the Inspect bridge, so each bundle carries an Inspect log and
  verifies like every other bundle in the project.
- The suite report separates advisory content into a distinct panel labelled "not binding, gates
  nothing"; 25 such panels appear in `report.html`.
- No cloud credentials and no network model provider were used. The manifest for this lane
  authorizes **no** model endpoint at all.

## Defects found and fixed during acceptance

Each was found by a command that failed, and each fix is covered by a test that fails when reverted.
The first two were found by a deliberate audit *after* the phase was otherwise complete, and both
were gaps between what this document claimed and what was actually executed.

- **The model plane's runtime enforcement was never executed by a test.** This was the most
  consequential finding of the phase. The two-plane split (ADR 0008) is Phase 3's headline security
  claim, and its *schema* enforcement was tested — a model origin cannot coincide with a target
  asset, target assets stay loopback, an offline engagement grants no endpoint. But its *runtime*
  path had never run: the offline provider reports no endpoint, so `ModelClient._authorize`
  returned immediately and `SafetyRuntime.authorize_model` was unreachable. `MODEL_ENDPOINT_NOT_SIGNED`
  and `MODEL_ENDPOINT_RESOLVES_TO_TARGET` appeared in the source and in no test. The claim that a
  rebind onto the fixture is refused was therefore an assertion about code I had written rather than
  a measured fact. `tests/phase3/test_model_plane.py` now executes that path: a signed origin is
  permitted and charged, an unsigned origin is denied and charged, a signed origin resolving onto a
  signed target endpoint is refused, an ungranted plane refuses everything, and each decision is
  recorded as a policy event carrying its resolved addresses.
- **A module docstring claimed a test that did not exist.** `adapters/agent.py` stated that a test
  greps it for adapter dispatch and tool paths. No such test existed — the same failure mode as the
  `AgentToolIntent` docstring below, which makes it a pattern rather than a slip. The test now
  exists and passes: the agent module imports no adapter, names no tool path, opens exactly one HTTP
  client, and contains no URL literal at all. Two adjacent invariants were untested for the same
  reason and are now covered: no registered operation can name an origin, and no exception handler
  in the provider module falls back to the offline store.
- **The agent lane had no fault-injection coverage.** Phase 2 injected failure and cancellation at
  every lifecycle stage; Phase 3 added new adapters, a model call, and a utility-under-attack pass
  without extending it. All eleven stages are now injected in both raising and cancelled form, plus
  a mid-leg model-provider failure. Every case tears down, closes the fixture, and retains evidence.
  One case documented a design decision rather than a defect: cancellation *during* teardown is
  deliberately recorded rather than propagated, because the cleanup path is shielded so evidence is
  still flushed.
- **The redactor masked a numeric decoding parameter.** `max_output_tokens` matched the
  sensitive-key heuristic on the substring "token", so every `MODEL` event recorded `[REDACTED]`
  where a decoding parameter belongs — the same class of defect Phase 2 hit with a flag named
  `function_authorization`. Fixed by extending the explicit integer-only allowlist, not by
  loosening the matcher: a credential is never a bare int.
- **Exfiltration was unmeasurable, and the reason mattered.** The runtime returns the redacted
  adapter result, so a real canary is stripped out of model output before the runner sees it. A
  canary cannot travel through the harness into a tool call, and the only way to score exfiltration
  by canary string would have been to weaken the redactor. It was not weakened; the internal note
  carries a non-secret tracer instead, and the real canaries stay in the redactor's secret list.
- **The oracle hash leaked per-run identifiers.** New `LegResult` fields carried evidence ids into
  the semantic hash, so two identical runs produced different oracle hashes and replay determinism
  read 0/75. Fixed with a single named exclusion set covering every evidence-id field; replay then
  measured 75/75.
- **The evidence-completeness metric was not reason-aware.** An `ORACLE` event is now emitted for
  two different things, and the utility-under-attack pass decides only utility. Requiring a
  security field on it would have invited a null placeholder, which is how a completeness metric
  becomes decorative. Required fields can now depend on the reason code.
- **`DetectorResult.time_to_detect` had no default**, so a bundle written with `exclude_none` could
  not be reloaded whenever an expected detector rule never fired. Earlier lanes never hit it
  because their defended replays still emit a blocked event carrying the rule id; an agent-lane
  replay that stops the attack upstream emits nothing for that rule at all.
- **The base64 pattern required a trailing word boundary**, which dropped `=` padding and made
  every padded blob fail strict decoding, so the encoded-injection scenario read as inconclusive
  rather than as a finding.
- **The fixture's defense registry was the Phase 2 map**, so every agent-lane defense was rejected
  as not applicable.
- **The adapter silently dropped invalid intents** and applied the per-turn cap before validating,
  so a model could push an invalid intent out of inspection by padding the list ahead of it.
- **`AgentToolIntent` did not type its arguments** despite a docstring claiming it did.

### Found by CI

- **The adaptive attacker contaminated the state its own scenario was scored on.** `agent-demo`
  enables the attacker; the corpus-metrics run above does not. With it enabled,
  `agent-indirect-markdown` regressed: its security oracle counts rows in `crm_records`, and the
  attacker's accepted proposals write to that table. The defended replay held 3 attacker rows and 0
  from the injected intent — the defense had worked perfectly — but the oracle still read "true", so
  the defense was never credited. Detection was affected the same way: an attacker write to a
  privileged field fired the `privileged-field` rule inside a defended replay, which is a false
  detector signal. Rejected proposals were designed as evidence; accepted ones landing in scored
  state was not thought through.

  Fixed by ordering rather than suppression: the probe still runs, under the leg's defense
  configuration and charged to the same attack budget, with every decision recorded — but after the
  state and telemetry the oracles read have been captured. `tests/phase3/test_attacker_isolation.py`
  asserts a scenario reaches the same verdict and the same observed detector set with the attacker
  on and off, and that accepted and refused proposals both still occur, so it cannot pass by the
  probe having been disabled.

  **This also corrected a reported number.** The executed-unauthorized-side-effects figure in the
  four-number table was measured with the attacker on and counted the probe's own writes. It is
  re-measured below.

- **A process failure of mine, recorded because it caused the above to be missed.** I ran
  `agent-demo` through `tail` and read "Verified report" as success without checking the exit code.
  The demo had already been exiting 1 on this scenario locally. The 25/25 figure elsewhere in this
  record came from a separate corpus-metrics run with the attacker off, so both statements were
  true of different configurations, and I conflated them. CI caught it because CI checks exit codes.

### Found on the container lane

- **The agent surface could not be seeded on PostgreSQL.** The control route called `seeding.apply`,
  which materializes, and then wrote the agent corpus into the template and materialized again.
  SQLite keeps its template connection open after materializing, so this worked in every in-process
  run. PostgreSQL commits and closes the template so it can serve as `CREATE DATABASE … TEMPLATE`, so
  the agent-row write failed with `AttributeError: 'NoneType' object has no attribute 'execute'`,
  reproduced against a PostgreSQL 16 container. Every agent scenario would have failed at seed time
  on the container lane. The in-process record could not see this: its 25/25 and 75/75 figures were
  true, and true only for SQLite. Fixed by seeding every row before a single materialize.
  `tests/phase3/test_seed_materialize.py` enforces PostgreSQL's rule on the in-process engine — the
  template is unwritable once materialized — so this class of defect now fails without a container,
  and a container-gated case asserts the cross-engine hash.

## Coverage exclusions

- **None new in Phase 3.** `OpenAICompatibleProvider` was initially excluded as "stochastic lane
  only"; it is now driven through a stub transport and `model_provider.py` measures **100%**
  statement and branch coverage. Every contract behaviour is exercised against that stub: endpoint
  authorization before connect, a denied endpoint stopping the request before it is sent, bounded
  output, token and cost charging, a cap breach failing closed, a redirect refused as a denial
  rather than followed as a hop, error statuses surfaced, malformed responses refused rather than
  guessed at, the credential reaching the header and never the record, a deadline cancelling the
  call, and the pin's decoding parameters and seed actually appearing in the request body.
- The Phase 2 container and browser exclusions are unchanged.

What the stub cannot cover is a real endpoint's behaviour — latency, rate limiting, partial
responses, provider-specific error shapes. That is the stochastic lane, and it is Phase 4 debt
(PRD WP4.0), not a coverage exclusion.

## Known limits

- **No real model was called.** Every number here was produced with `ScriptedAgentModel`, a
  deterministic susceptibility simulator with one declared behaviour: it follows instructions
  inlined with retrieved content and does not follow the same instructions when they are delimited
  as data. That is a real, documented phenomenon and it exercises the defense end to end — but it
  is a stand-in, and no result here is evidence about any real model's susceptibility, resistance,
  or cost. The stochastic lane exists (`--endpoint`, `make agent-stochastic`, the nightly CI job)
  and has not been run against a real endpoint.
- For the same reason, the PRD's "token and API cost within ±10%" checkpoint is met for **tokens**
  and is met **vacuously** for API cost, which is a measured zero. A real-cost figure needs the
  stochastic lane.
- The judge agreement and evaluator-resistance figures measure the harness's hardening, not a
  model's judgement. A perfect score from a deterministic stand-in is not a claim about a real
  judge. The negative control is what makes those numbers informative.
- Retrieval is exact lexical matching with no embeddings (ADR 0011). The corpus does not cover
  embedding-based retrieval, and does not imply it.
- `supportlab` has **no code-execution surface**, so no scenario claims an unexpected-code-execution
  finding. That threat is covered as a containment property instead: an operation outside the closed
  vocabulary is refused and recorded. Claiming a code-execution finding against a fixture that
  cannot execute code would be fabricating a result.
- `ModelClient` is not a plan-reachable adapter and so cannot run the shared adapter contract suite
  by dispatch; its behaviour is covered by dedicated tests. This is the deliberate cost of the
  two-plane split and is recorded in ADR 0008, not a skipped requirement.
- Detection delay is still measured in injected logical ticks. Real token counts sitting beside it
  do not make it a wall-clock or billing claim.
- A passing run is evidence about these exact fixtures, seed, defenses, and provider only. It does
  not prove a target or a model is secure, and harness authorization never makes an application
  authorization failure legitimate.
