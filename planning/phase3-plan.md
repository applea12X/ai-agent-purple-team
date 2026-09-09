# Phase 3 implementation plan — LLM/RAG agent and adaptive attack lane

**Status: proposed.** Section 8, Phase 3 of [PRD.md](PRD.md) is authoritative; where this document
and the PRD disagree, the PRD wins. On completion this plan is superseded by an as-built design
note (`docs/phase3-plan.md`, matching the Phase 1 and Phase 2 pattern) and a measured record in
`docs/phase3-acceptance.md`.

---

## 0. Verified starting point

Commit `b4d9ec5`. Measured in [docs/phase2-acceptance.md](../docs/phase2-acceptance.md): 166 tests
passed with 2 container-gated skips, 87.03% branch coverage, 18 labelled `supportlab` scenarios
(13 API, 5 browser) plus the 5 Phase 1 scenarios, API-lane replay 1.0, browser-lane replay
(HTML-form driver) 1.0 reported separately, 100 consecutive isolated runs with 0 failures,
evidence-field completeness 1.0, and zero unintended cross-tenant access by the harness.

### What exists and is reusable as-is

| Area | Module | Reuse in Phase 3 |
| --- | --- | --- |
| Per-action authority | `runtime/runtime.py` (`SafetyRuntime`) | Unchanged. Still the only path to I/O, including for every tool a model asks for. |
| Lifecycle | `runtime/runner.py` (`PurpleTeamRunner`) | Extended with repetition and judging stages, not replaced. |
| Lane parameterization | `control/lanes.py` (`LaneContract`) | The extension point for the agent lane. A third lane, not a third runner. |
| Plan compilation | `control/plan_compiler.py` (`compile_plan`, `compile_step`) | Extended with agent nodes. `compile_step` is already the path dynamic tool intents take. |
| Tool contracts | `control/tools.py`, `control/phase2_tools.py` | Reused; agent tools are ordinary `ToolDefinition`s with typed argument models. |
| Budget ledger | `control/budgets.py` (`BudgetLedger`) | Reused unchanged. `BudgetRequest`/`BudgetLimits` **already carry `tokens` and `cost_microusd`**; Phase 3 populates them from real accounting rather than adding fields. |
| Credential broker | `control/credentials.py` | Reused. A model API key becomes another opaque handle. |
| Redactor | `control/redaction.py` | Reused, and now load-bearing for model-provider secrets in evidence. |
| Oracles | `scoring/phase1.py` (`evaluate`, closed operator set) | Unchanged and still primary. Judges never widen the operator set. |
| Corpus metric | `scoring/phase1.py` (`corpus_metrics`) | Reused; corpus grows, metric shape does not change. |
| Evidence metric | `scoring/phase2.py` (`evidence_completeness`) | Reused; new event kinds add required fields. |
| Ownership | `schemas/phase2.py` (`Phase2Grants.owner_of`) | Reused. Ownership stays signed manifest data. |
| Evidence bundle | `reporting/bundle.py` | Extended with judge transcripts and repetition sets. |
| Inspect bridge | `runtime/inspect_bridge.py` | Extended: the offline provider stays registered and default; a real provider is an alternative model string, not a fallback. |
| Fixture app | `fixture/supportlab/` | Extended with agent, retrieval, and memory surfaces on the same deterministic clock and seed. |

### What does not exist yet

No RAG or retrieval surface, no memory store, no agent tools beyond the four API write tools, no
model provider other than `OfflineModelStore`, no outbound network path of any kind, no adaptive
attacker, no judge, no repetition/aggregation machinery, no third-party scenario importers, and no
evaluator-red-team corpus.

### Constraints inherited from Phase 2 that shape this phase

- `ChatResult.tool_intents` is capped at **one** intent (`control/phase1_tools.py:62`). An agent
  that plans a multi-step tool sequence needs more than one; raising this cap is a deliberate
  authority-surface change, not a constant edit (§3.4).
- `HttpAdapter.preflight` rejects any scheme other than `http` (`adapters/phase1.py:39`), because
  every registered target has been a loopback fixture. A real model API is HTTPS and off-host.
- Every containment posture to date is **no egress**. The fixture, the database, and the upstream
  container all sit on an internal-only network. Phase 3 introduces the project's first outbound
  call, and it must not be introduced by relaxing the fixture's posture (§2.2).
- `Finding.reproducible` is hard-coded `False` in `runtime/runner.py` because a single paired run
  cannot establish reproducibility. Repetitions make this field answerable for the first time.
- Detection delay is measured in injected logical ticks, and budget tokens have so far been
  reserved capacity rather than consumption. Phase 3 makes the token half real; the tick half
  stays logical and must keep saying so.
- `supportlab`'s schema (`fixture/supportlab/schema.py`) has no `chunks`, `memory`, or
  `agent_runs` tables. Adding them changes the canonical snapshot surface and therefore every
  seed hash (§3.5).

---

## 1. Objectives

1. Add an LLM/RAG agent surface inside `supportlab` whose every tool call goes through
   `SafetyRuntime`, with provenance-tagged retrieval so an indirect injection traces back to the
   document that delivered it.
2. Add real model providers behind a broker-held credential, with per-event model pinning and
   token/cost budgets that fail closed — while the offline provider stays the default and the CI
   default, and a missing credential skips the lane rather than silently reaching the network.
3. Grow the corpus to 30–50 labelled scenarios covering the agentic and LLM threat classes, with
   versioned taxonomy mappings validated by a schema test.
4. Add a bounded adaptive attacker whose output is untrusted data through the existing compiler,
   and importers that normalize third-party cases into PurpleLoop scenarios.
5. Add a hybrid judge that runs only where deterministic oracles abstain, and a dedicated
   evaluator-red-team corpus that attacks the judge on purpose.
6. Report stochastic results honestly: four separate numbers, ≥5 repetitions with confidence
   intervals, and every figure carrying its n, seed policy, and model pin.
7. Do all of the above without weakening a Phase 0, 1, or 2 invariant, and without touching those
   three lanes.

### The contract change, stated once and enforced everywhere

> Deterministic oracles remain primary and binding. Stochastic components produce **advisory**
> signals only. Every reported verdict records which kind produced it. **No stochastic result may
> gate a release-blocking invariant.**

This is not a documentation statement. It is §3.1, it is a type, and it is a test that fails if a
release gate ever reads an advisory field.

### Non-goals for this phase

Fine-tuning or training anything; model-vs-model comparison matrices (Phase 5); a human-review UI;
autonomous remediation of the fixture; production or non-fixture targets; and any expansion of the
adapter set beyond the agent surface. The `phase0`, `phase1`, and `phase2` lanes are not edited.

---

## 2. The hard problems

Everything else in this phase is ordinary engineering. These four are where the phase fails if it
fails, so they get designed before any code is written.

### 2.1 The determinism boundary is now inside a single run

Phases 1 and 2 had one kind of verdict. Phase 3 has three, and they will appear side by side in
the same summary, the same bundle, and the same report:

| Class | Produced by | Binding? | Replayable? |
| --- | --- | --- | --- |
| `deterministic` | Closed-operator oracle over state, responses, telemetry | Yes — gates status, findings, and CI | Bit-exact |
| `advisory` | LLM judge, model susceptibility signal, adaptive-attacker outcome | No | Not claimed; variance is measured and reported |
| `pinned-stochastic` | Real model call with a recorded pin, seed, and decoding params | No | Reported as a measured reproduction rate, never asserted |

The failure mode to design against is *silent promotion*: an advisory number leaking into a
denominator, a status field, or a gate, and inheriting the credibility of the deterministic ones.

**Design:** a `VerdictProvenance` discriminator is a required field on every scored artifact
(`OracleResult`, `JudgeResult`, `Finding`, and the per-repetition record). `RunSummary.status`,
`corpus_metrics`, and every CI gate read only artifacts whose provenance is `deterministic`. A
test constructs a summary in which the deterministic oracle says `false` and the judge says `true`,
and asserts the run status, the finding set, and every gate are unchanged. A second test asserts
that an advisory value placed in each gate's input path is rejected at the type boundary rather
than being averaged in. This mirrors the `corpus_metrics` rule: the metric ships with a test that
fails when the metric is faked.

### 2.2 The first egress, without relaxing the fixture's no-egress posture

A real model call is an outbound HTTPS request from the harness process. Every containment
guarantee measured so far — up to and including "external egress to `1.1.1.1:443` refused" — was
about the *fixture*. Conflating the two would quietly delete the strongest control in the project.

**Design — two separate planes, never merged:**

- **Target plane.** `supportlab`, PostgreSQL, and the upstream container keep the exact Phase 2
  posture: internal-only network, no published ports, no egress, loopback ingress relay. Nothing
  in Phase 3 changes a single line of that compose contract, and the existing isolation test
  (which asserts refused egress) runs unchanged as a regression.
- **Model plane.** The model provider is an authorized external asset declared in the signed
  manifest with an exact host, port, and scheme, and reached only by a new `ModelAdapter` — never
  by `HttpAdapter`, whose `http`-only preflight stays as it is. The adapter is subject to the same
  target-authorization path (`control/targets.py` canonicalization, DNS-resolution checks,
  redirect refusal — a model endpoint that redirects is a denial, not a hop) and the same budget,
  cancellation, redaction, and evidence rules as every other adapter.
- **The fixture never calls a model.** The agent's model calls are made by the harness on the
  agent's behalf and handed back as data. If the fixture itself needed egress, the whole
  containment story would collapse; it does not, and a test asserts the fixture container's
  network configuration is byte-identical to Phase 2's.

This split is the phase's most consequential architectural decision and gets ADR 0008.

### 2.3 The judge reads attacker-controlled evidence

The judge's input is normalized evidence, and in an indirect-injection scenario that evidence
contains, by construction, text written to manipulate a language model. The judge is therefore not
merely fallible — it is *targeted*.

**Design:**

- Judge input is a rendered, typed, length-bounded evidence view — never raw ledger JSON, never
  raw page or document bodies. Untrusted spans are structurally delimited and explicitly labelled
  with their provenance and trust level (which §3.5's retrieval provenance already carries).
- The judge returns a closed structured verdict — `{verdict, cited_evidence_ids, confidence,
  rationale}` — validated against a strict model. A citation naming an evidence ID that is not in
  the input is an automatic abstention, not a parse fix-up.
- **Abstention is a recorded first-class outcome**, not a failure and not a `false`.
- The judge cannot mint evidence, name a target, propose an action, alter a budget, or change a
  finding's status. Its output reaches the report and nothing else.
- The evaluator-red-team corpus (WP3.5) is built and its human labels frozen **before** the judge
  is tuned, then held out and versioned. Tuning against the held-out set is the one way this
  checkpoint becomes meaningless, so the split is enforced by a test over file digests rather than
  by discipline.

### 2.4 Stochastic cost and time, at 5 repetitions

30–50 scenarios × paired legs × ≥5 repetitions × real model calls is where this phase becomes
expensive and slow enough to be quietly skipped. That is exactly how a checkpoint decays into an
assertion.

**Design:** a pre-run token and cost estimate per scenario, aggregated per suite and reported
against actual with the same ±10% machinery `scoring/phase2.py::resource_report` already
implements for requests and browser contexts. A hard cap that terminates fail-closed and records a
**budget outcome, not an error**. The nightly lane, not the PR lane, carries the repetitions; the
PR lane stays offline, deterministic, and fast. A skipped repetition is reported as a reduced n
beside the number it affects — never dropped from a denominator.

---

## 3. Contract changes

Every change is additive and versioned. Phase 0, 1, and 2 manifests, scenarios, ledgers, and
bundles must continue to load, verify, and produce **byte-identical** canonical bytes and digests.
This is a test, not an intention — `tests/phase2` already asserts it for the 1.2 additions and the
same assertion extends to 1.3.

### 3.1 `VerdictProvenance` — the type behind §2.1

```
VerdictProvenance = Literal["deterministic", "advisory", "pinned-stochastic"]
```

Required on `OracleResult`, the new `JudgeResult`, `Finding`, and `RepetitionRecord`. Existing 1.1
and 1.2 documents default to `deterministic`, which is what they have always been, so their
canonical bytes are unchanged. Gate-reading code accepts only `deterministic`.

### 3.2 Manifest 1.3

Adds `Phase3Grants`:

- `model_assets`: exact scheme/host/port endpoints authorized for model calls, disjoint from every
  target asset. Validated as origins with no path, the way `subresource_origins` already is.
- `model_credential_handle`: broker handle; never in model context, never in evidence.
- `model_pins`: the exact model IDs authorized, with decoding parameters and, where the provider
  exposes one, a version or digest. An unpinned model is not runnable.
- `token_budget` / `cost_microusd_budget`: hard caps, enforced by the existing ledger fields.
- `max_agent_steps`, `max_tool_intents_per_turn`, `max_attacker_proposals`,
  `max_attacker_depth`: the caps for §3.4 and WP3.4.
- `judge_enabled` and `judge_model_pin`: the judge is off unless the signed manifest turns it on.

Manifest 1.0, 1.1, and 1.2 keep exactly their current grants and canonical serialization.

### 3.3 Scenario 1.3

Adds:

- `surface` gains `agent` (alongside `api`, `browser`, `both`).
- `injection_channel`: closed enum — `ticket`, `document`, `html`, `markdown`, `api-response`,
  `tool-description`, `memory`, `log`, `inter-agent`. The PRD requires at least one scenario per
  channel; a corpus-coverage test asserts every channel is populated rather than leaving it to
  review.
- `agent_task`: the agent's legitimate objective and its declared per-task capability set — a
  subset of the lane's tools, resolved at compile time.
- `judge_rubric_id`: optional reference into a versioned rubric catalogue, resolved the way
  `shared_oracle` already resolves through `oracles.yaml`.
- `repetitions`: default 1 for deterministic scenarios, ≥5 for stochastic ones.
- `taxonomy_mappings` gains a **required-key schema test** for the five pinned taxonomies (OWASP
  LLM/GenAI 2025, OWASP Agentic 2026, MITRE ATLAS, ASVS 5.0, API Security Top 10 2023). Imported
  cases additionally require `provenance` and `license`, which the model already carries.

### 3.4 Multi-intent chat and the agent step

`ChatResult.tool_intents` rises from `max_length=1` to `max_length=N`, where N comes from
`manifest.phase3.max_tool_intents_per_turn` rather than a literal. Each intent still goes
one-at-a-time through `compile_step` → `SafetyRuntime`; raising the cap raises the *number* of
authorized actions, never the authority of any one of them. The existing dynamic-node accounting
in `runner.execute_steps` (which already charges intents against `max_nodes`/`max_depth` and the
leg budget) is the enforcement point, and it needs a property test at the new cap.

`ToolIntent.operation` widens from the Phase 1 literal (`canary.export`) to the agent lane's
declared per-task capability set — still a closed enum resolved from trusted registry data, never
a free string from model output.

### 3.5 Retrieval, memory, and the snapshot surface

New `supportlab` tables — `chunks` (with `source_id`, `trust_level`, `provenance`), `memory`, and
`agent_runs` — join the canonical ordered snapshot. Adding them changes every seed hash. That is
expected and must be handled explicitly:

- The agent lane is a **third lane** with its own seed and its own recorded seed hash. The Phase 2
  lane's seed hash (`5c270cdd…` for seed 42) stays exactly as it is, asserted by the existing test.
- All four Phase 2 determinism mitigations apply unchanged to the new tables: explicit total
  ordering on every query feeding scored output, seed-derived identifiers, no `now()`/`random()`
  in application queries or seed data, snapshot hash from a canonical ordered `SELECT` through the
  JCS path.
- Retrieval is deterministic: a fixed embedding-free ranking (exact/lexical over seeded chunks
  with a total order and stable tie-break), so *retrieval* stays replayable even when *generation*
  does not. Vector search with a real embedding model is explicitly out of scope for this phase —
  it would move retrieval into the stochastic class for no scenario-coverage gain.

### 3.6 New event kinds

`EventKind` gains `MODEL` (a pinned model call: model ID, pin, decoding params, seed, system-prompt
hash, prompt/response digests, token counts, cost), `JUDGE` (rubric ID and version, input digest,
verdict, citations, confidence, abstention), and `PROPOSAL` (an attacker proposal and its
accept/reject decision with reason code). Each gets required fields in
`scoring/phase2.py::KIND_FIELDS` so evidence completeness covers them from the first run.

---

## 4. Work packages

### WP3.0 — Clear Phase 2 debt

Small, and a prerequisite for trusting Phase 3's own numbers.

| # | Task | Done when |
| --- | --- | --- |
| 3.0.1 | Land §3.1 `VerdictProvenance` and its gate tests **before** any stochastic component exists | A judge cannot be wired in without a provenance field, because the type requires one. |
| 3.0.2 | Make `Finding.reproducible` answerable | It is computed from the repetition set (WP3.6), not hard-coded. Single-repetition runs report `reproducible=False` *and say why*. |
| 3.0.3 | Reconfirm the container-lane coverage exclusions named in `docs/phase2-acceptance.md` | Each is still container-only, or it is now covered. The list does not grow silently. |
| 3.0.4 | Extend the `PYTHONHASHSEED` CI matrix to the new lane | The JCS/`frozenset` class of defect cannot regress into agent-lane canonicalization. |
| 3.0.5 | Keep detection delay labelled as logical ticks wherever tokens become real | Reporting cannot imply that one real number makes the other one real. |

### WP3.1 — Agent surface inside `supportlab`

Files: `src/purpleloop/fixture/supportlab/agent.py`, `retrieval.py`, `memory.py`; schema additions
in `schema.py` (with the generated `.sql` kept in sync by the existing drift test);
`src/purpleloop/control/phase3_tools.py`; `AGENT_LANE` in `control/lanes.py`.

| # | Task | Notes |
| --- | --- | --- |
| 3.1.1 | RAG assistant with document ingest and deterministic retrieval | Ranking is exact and totally ordered (§3.5). Every chunk carries `source_id`, `trust_level`, and provenance into evidence. |
| 3.1.2 | Memory store | Read and write are separate typed tools with separate capabilities. Memory poisoning is a scenario, so memory must be *writable* by the agent and *scored* by a state oracle. |
| 3.1.3 | Narrow agent tools: email, CRM, refund, export, memory | Typed schemas, idempotency keys, declared per-task capability set. Email and CRM are new synthetic surfaces; refund and export reuse the existing workflow tools and their existing defenses. |
| 3.1.4 | All tool execution through `SafetyRuntime` | The assistant parses intents; it never invokes a tool. Enforced by a test that greps the agent module for any adapter or HTTP call and fails on a hit — the same shape as Phase 2's ordering test. |
| 3.1.5 | Hostile-content channels | Ticket, document, HTML, Markdown, API response, tool description, memory, log, inter-agent message. Each is a real ingestion path in the fixture, not a scenario string. |
| 3.1.6 | Provenance tagging end to end | Given a finding, the delivering document is recoverable from evidence alone. Tested by asserting the chain, not by reading a bundle. |

Containment is unchanged from Phase 2 (§2.2, target plane).

### WP3.2 — Model providers beyond offline

Files: `src/purpleloop/adapters/model_provider.py`, `src/purpleloop/control/model_pins.py`.

| # | Task | Notes |
| --- | --- | --- |
| 3.2.1 | OpenAI-compatible `ModelAdapter` with configured-API and Ollama/vLLM profiles | Registered like any other adapter. Separate from `HttpAdapter`; the `http`-only preflight is not touched. |
| 3.2.2 | Offline stays the default and the CI default | A missing credential **skips the lane and records the skip**. There is no fallback path from a real provider to the offline store, and a test asserts no code path performs one. |
| 3.2.3 | Per-event model pin | Model ID, version/digest where available, decoding parameters, seed where supported, system-prompt hash — on every `MODEL` event. |
| 3.2.4 | Real token and cost accounting | Charged through the existing `BudgetLedger` fields. A cap breach terminates fail-closed with a **budget outcome**, distinct from an error. |
| 3.2.5 | Broker-held model credentials | Absent from model context and from evidence; covered by the existing redaction tests extended to the new event kinds. |
| 3.2.6 | Model endpoint authorization | Exact scheme/host/port from the signed manifest; DNS-resolution check before connect; a redirect from a model endpoint is a denial, not a hop. |

### WP3.3 — Corpus to 30–50 scenarios

Present: 18 `supportlab` + 5 Phase 1 = 23 labelled scenarios. Phase 3 adds **12–27**, targeting
roughly 20 new agent-surface cases for a corpus of ~43.

Required coverage (PRD): direct and indirect injection including encoded, multilingual, and
multiturn variants; system-prompt leakage; RAG poisoning; memory poisoning; goal hijacking;
confused-deputy; excessive agency and tool misuse; argument and schema injection; unsafe output
handling; canary exfiltration and covert channels; unexpected code execution; cascading failure;
human-approval spoofing.

Every scenario keeps the established shape — vulnerable seed, clean utility task, baseline attack,
positive control, clean or defended negative control, **deterministic** oracle, expected detector
behavior, one pre-approved defense — and every one is labelled in `ground-truth.json`. An
unlabelled scenario continues to raise rather than be skipped.

Two rules specific to this phase:

- **Every scenario needs a deterministic security oracle.** "The model said something bad" is not
  a finding. Canary exfiltration is scored by canary state, tool misuse by executed side effects,
  approval spoofing by the approval record. If a threat cannot be reduced to a state, response,
  or telemetry assertion, it is authored so that it can be — or it is not in the corpus.
- **Model susceptibility and executed side effects stay separate columns**, as the Phase 1
  invariant requires. A scenario where the model complies but the kernel blocks the tool call is a
  *susceptibility* result and an *enforcement success*, and it is reported as both.

New defense profiles enter the versioned registry alongside the Phase 2 seven — provisionally
`retrieval-provenance-guard`, `capability-scoping`, `output-sanitization`, `approval-verification`,
`memory-write-guard` — each a named configuration value the signed manifest must pre-authorize.
The harness never edits fixture source.

### WP3.4 — Bounded adaptive attacker and third-party imports

Files: `src/purpleloop/control/attacker.py`, `src/purpleloop/adapters/imports/`.

| # | Task | Notes |
| --- | --- | --- |
| 3.4.1 | Attacker proposes **typed plan nodes only** | Output goes through `compile_step` as untrusted data. No new adapters, no new targets, no scope widening, no free-form strings outside typed argument models. |
| 3.4.2 | Attempt, depth, and budget caps from the signed manifest | Enforced in the existing dynamic-node accounting path, not in the attacker. |
| 3.4.3 | A rejected proposal is **evidence, not an error** | Recorded as a `PROPOSAL` event with a reason code. The run continues. A rejection rate is a reported number. |
| 3.4.4 | Importers for PyRIT, garak, Promptfoo, AgentDojo-style cases | Each normalizes into a PurpleLoop scenario with `provenance` and `license` required. No imported framework owns the canonical schema. |
| 3.4.5 | Imported payloads are data | An imported case that cannot express a deterministic oracle is imported as **not-runnable** with recorded conversion issues — exactly how `load_scenario` already handles 1.0 documents — never auto-promoted. |

### WP3.5 — Hybrid judge and evaluator red team

Files: `src/purpleloop/scoring/judge.py`, `scenarios/evaluator-redteam/`, `docs/judge-rubrics/`.

| # | Task | Notes |
| --- | --- | --- |
| 3.5.1 | Deterministic oracle first; judge only on unresolved semantics | The judge does not run when the oracle returns `true` or `false`. Tested. |
| 3.5.2 | Structured rubric over normalized evidence | Closed output model; cited evidence IDs validated against the input set; uncited or invented citations force abstention. |
| 3.5.3 | Abstention is a recorded outcome | Never coerced to `false`, never counted as a judge failure. |
| 3.5.4 | Repeated trials and order swaps | ≥5 trials; position-swapped presentations; consistency reported as a number. |
| 3.5.5 | Evaluator-red-team corpus | Evidence-borne injection, fake approvals, scope-widening claims, rubric gaming, verbosity bias, position bias, self-family bias, unsupported citations. Each is its own labelled case. |
| 3.5.6 | Human-adjudicated labels frozen before tuning | Built first, digest-pinned, held out, versioned. A test asserts the held-out digest is unchanged across the tuning commits. |
| 3.5.7 | Agreement measured, not asserted | Cohen's kappa (or Krippendorff's alpha where abstention makes kappa ill-defined), reported with n and a confidence interval. |

### WP3.6 — Reporting for stochastic results

| # | Task | Done when |
| --- | --- | --- |
| 3.6.1 | Four separate numbers | Clean utility, utility under attack, attack success, executed unauthorized side effects — never combined into one score. `utility_under_attack` is a new measurement, not a re-label of an existing one. |
| 3.6.2 | Repetition machinery | ≥5 repetitions per stochastic scenario; a `RepetitionSet` carrying per-trial records, the aggregate, and its confidence interval. |
| 3.6.3 | Every stochastic figure carries n, seed policy, and model pin | Enforced by the schema; a figure without them does not serialize. |
| 3.6.4 | Per-risk-class reporting with worst cases, exclusions, provenance | Alongside any aggregate, never instead of it. |
| 3.6.5 | Token/cost estimate vs actual | Same ±10% machinery as `resource_report`, extended to `tokens` and `cost_microusd`. |
| 3.6.6 | Deterministic and stochastic sections are visually and structurally separate in the HTML report | An advisory number cannot be mistaken for a binding one at a glance. |

### WP3.7 — CI, decision records, and acceptance

- New `.github/workflows/phase3.yml`: a **deterministic lane** (offline provider, no credentials,
  `PYTHONHASHSEED` matrix) and a **nightly/manual stochastic lane** (real model calls from
  repository secrets, ≥5 repetitions). `phase0.yml`, `phase1.yml`, and `phase2.yml` are not edited.
- `make phase3-check` and `make phase3-demo`, following the existing naming.
- ADRs: **0008** model-plane egress separate from the target plane (§2.2); **0009** advisory versus
  binding verdict provenance (§2.1); **0010** judge input normalization and abstention semantics
  (§2.3); **0011** deterministic retrieval without embeddings (§3.5).
- Any code executing only in the stochastic lane is named as a coverage exclusion in the acceptance
  record, the way `relay.py` and `PlaywrightDriver` were.
- `docs/phase3-acceptance.md` recording measured results, defects found during acceptance, and
  known limits.

---

## 5. Test plan

- **Unit** — Manifest 1.3 and Scenario 1.3 round-trips with byte-identical legacy canonical bytes;
  verdict-provenance defaults; judge output validation including invented-citation rejection;
  token/cost charging arithmetic; taxonomy required-key schema test; retrieval ranking totality
  and tie-break stability; repetition aggregation and confidence-interval computation.
- **Property** — mutations of model endpoint host/scheme/port/redirect; tool-intent operations
  outside the declared capability set; intent counts at and above the cap; attacker proposals
  naming new adapters, new targets, other tenants, or widened budgets. Every unauthorized mutation
  denied before any adapter I/O.
- **Contract** — `ModelAdapter` runs the same shared adapter suite as HTTP, tool, and browser
  adapters: typed I/O, deadlines, cancellation, kill-switch cooperation, idempotency, redaction,
  bounded output, no hidden network fallback. No exemptions; a genuine impossibility is an ADR,
  not a skip.
- **Gate isolation (§2.1)** — a summary where the judge disagrees with the oracle leaves status,
  findings, `corpus_metrics`, and every CI gate unchanged; advisory values are rejected at each
  gate's type boundary.
- **Containment regression (§2.2)** — the Phase 2 container isolation test passes unchanged; the
  fixture's compose network configuration is asserted byte-identical; a test asserts the fixture
  never opens an outbound socket even while the harness is calling a model.
- **Compromised-target property test** — the PRD checkpoint "no out-of-scope action reaches the
  target even when the target model is compromised" is a property test: a hostile model stub that
  emits maximally adversarial tool intents on every turn, run against the full authorization path,
  asserting zero out-of-scope executions across a generated space of intents.
- **Evaluator adversarial** — the held-out red-team corpus, scored for injection resistance and
  critical false passes.
- **Integration** — full paired loops on the agent lane, per channel; provenance chain recoverable
  from evidence; susceptibility and executed side effects recorded separately.
- **Fault injection** — every lifecycle stage in both raising and cancelled forms, now including
  model-provider timeout, model-provider 429/5xx, token-cap breach mid-leg, judge timeout, and
  attacker-proposal storm. Every case tears down and leaves a verifiable partial bundle or an
  explicit evidence-integrity incident.
- **Regression** — Phase 0's 57, Phase 1's 133, and Phase 2's 166 pass unchanged; existing
  manifests, ledgers, and seed hashes keep byte-identical digests.

---

## 6. Acceptance checkpoint

Each number names how it is measured. Nothing is established by inspection or inferred from a
successful implementation.

| Checkpoint | Threshold | Measurement |
| --- | --- | --- |
| Corpus size | 30–50 labelled scenarios | Counted; every one labelled in ground truth, unlabelled raises. |
| Taxonomy mappings | Complete and versioned | Schema test over the five pinned taxonomies. |
| Injection-channel coverage | Every channel in §3.3 populated | Corpus-coverage test. |
| Four separate numbers | Reported separately | Clean utility, utility under attack, attack success, executed unauthorized side effects. Never composited. |
| Out-of-scope actions with a compromised target model | 0 | Property test with a hostile model stub, plus observation across the integration suite. |
| Judge agreement with adjudicated labels | κ or α ≥ 0.7 | Reported with n and a confidence interval, on held-out labels frozen before tuning. |
| Judge order-swap consistency | ≥ 95% | Swapped-presentation trials. |
| Held-out evaluator-injection resistance | ≥ 99%, no critical false pass | Held-out red-team corpus. |
| Token and API cost vs pre-run estimate | ±10% | `resource_report` extended to tokens and cost. |
| Deterministic lanes replay | Exactly as before | Normalized event and oracle hashes; no trial excluded. |
| Stochastic lane | Measured variance reported | Its own number, its own n; determinism is **not** claimed. |
| Repetitions | ≥ 5 per stochastic scenario, with CIs | Reduced n reported beside any affected figure. |
| Seeded recall / false positives | ≥ 90% / ≤ 5% | `corpus_metrics` over the expanded corpus, deterministic verdicts only. |
| Evidence-field completeness | ≥ 99% | `evidence_completeness`, extended to `MODEL`, `JUDGE`, `PROPOSAL`. |
| Prior suites | 57 + 133 + 166 passing, unchanged | Existing lanes. |
| Coverage | ≥ 85% branch | Floor, not target. |

---

## 7. Risks

| Risk | Impact | Mitigation |
| --- | --- | --- |
| An advisory number silently gates something | The project's central Phase 3 claim is false, and the failure is invisible | §2.1: provenance is a required type, gates read `deterministic` only, and a test asserts a disagreeing judge changes nothing. |
| Egress for models erodes the fixture's no-egress posture | The strongest measured control in the project quietly disappears | §2.2 two-plane split, ADR 0008, and the Phase 2 isolation test kept as an unchanged regression plus a fixture-socket assertion. |
| Judge is injected through the evidence it reads | Findings become attacker-controlled | §2.3 typed bounded input, delimited untrusted spans, citation validation, forced abstention, held-out red-team corpus. |
| Judge tuned against its own held-out set | The κ ≥ 0.7 checkpoint becomes meaningless | Labels frozen and digest-pinned before tuning; a test asserts the digest is unchanged. |
| Cost or wall time makes 5 repetitions impractical | The checkpoint decays into an assertion | §2.4 hard caps with budget outcomes; repetitions in the nightly lane only; reduced n reported, never hidden. |
| New tables change every seed hash | Phase 2's replay evidence looks broken | Agent lane is a third lane with its own seed hash; the Phase 2 hash assertion stays and must keep passing. |
| Raising the tool-intent cap widens authority by accident | A Phase 1 invariant regresses | Cap comes from the signed manifest; each intent still passes `compile_step` → `SafetyRuntime` individually; property test at the new cap. |
| Scope: agent + providers + 20 scenarios + attacker + judge in one phase | The phase stalls half-done | WP3.1 and WP3.2 are independent after §3 lands; WP3.4 and WP3.5 are independent of each other; only WP3.6 needs everything. Sequencing in §8. |
| A scenario has no deterministic oracle and gets scored by the judge alone | An advisory finding enters the corpus metric | WP3.3 rule: no deterministic oracle, no corpus entry. Enforced by `require_runnable`, which already refuses scenarios without typed oracles. |

---

## 8. Sequencing

```
WP3.0 (debt + VerdictProvenance)
   └─> §3 contracts (Manifest 1.3, Scenario 1.3, intent cap, event kinds, snapshot surface)
          ├─> WP3.1 agent surface ──┐
          └─> WP3.2 model providers ┴─> WP3.3 corpus ──┬─> WP3.6 stochastic reporting ─> WP3.7 CI + acceptance
                                                        │
                                    WP3.4 attacker ─────┤
                                    WP3.5 judge ────────┘
```

WP3.0's provenance type lands **first**, before any stochastic component exists, so that no judge
or model result can be wired in without declaring what kind of verdict it is. The §3 contract work
is a prerequisite for both build streams and should land as one reviewed change. WP3.1 and WP3.2
are independent. WP3.3 needs both. WP3.4 and WP3.5 are independent of each other and of the corpus
beyond a handful of cases each. WP3.6 needs everything, because it reports everything.

---

## 9. Open questions

Each needs a decision before the work package that depends on it starts. Recommendations given;
each becomes an ADR.

1. **Which real provider is the reference pin for acceptance?** A hosted API gives a realistic
   cost story but a moving target; a local Ollama/vLLM profile gives a reproducible pin and zero
   marginal cost. *Recommendation:* pin **both** — a local profile as the reproducible reference
   for the acceptance numbers, and one hosted model as the cost-estimate reference — and report
   them separately. Blocks WP3.2.
2. **Does the judge share the target's model family?** Self-family bias is on the evaluator
   red-team list, so the honest answer is to measure it. *Recommendation:* require the judge pin
   to be recorded, run the self-family bias case with target and judge from the same family, and
   report the delta rather than asserting independence. Blocks WP3.5.
3. **κ or Krippendorff's α?** Abstention makes plain Cohen's κ awkward — abstention is neither
   agreement nor disagreement. *Recommendation:* report α over a three-category scale
   (true/false/abstain), and κ over the abstention-excluded subset with its own n. Blocks WP3.5.7.
4. **How many repetitions in the nightly lane?** 5 is the PRD floor; the CI wall-time and cost
   consequences at ~43 scenarios need measuring before committing. *Recommendation:* measure the
   per-scenario stochastic cost early in WP3.2, then fix the number — and report it, whatever it
   is. Blocks WP3.6.2.
5. **Does the adaptive attacker use a real model or a bounded search?** A real model makes the
   attacker itself stochastic and expensive. *Recommendation:* start with a **bounded typed
   mutation search** over the existing payload space — deterministic, replayable, and sufficient
   to exercise the proposal/rejection path — and treat a model-driven attacker as an optional
   profile behind the same caps. Blocks WP3.4.
6. **Where does `utility_under_attack` get measured?** It is a new fourth number and there is no
   existing leg that produces it — the clean task runs before the attack, not during it.
   *Recommendation:* run the clean task **after** the attack in the same leg, on the same state,
   and record both. Blocks WP3.6.1.
7. **Do imported third-party cases count toward the 30–50?** *Recommendation:* only when they
   carry a deterministic oracle and a ground-truth label. Report imported and authored counts
   separately either way. Blocks WP3.3 sizing.
