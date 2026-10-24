# Phase 5 implementation plan — v1 closure and optional expansion

**Status: working plan, not started.** Section 8, Phase 5 of [PRD.md](PRD.md) is authoritative;
where this document and the PRD disagree, the PRD wins. On completion each work package is
superseded by its own as-built note and measured acceptance note under `docs/phase5/`, and
`docs/phase5-acceptance.md` becomes the index of which packages closed, which were dropped, and
why — matching the Phase 1–4 pattern, adjusted for the PRD's rule that Phase 5 items are
independent.

---

## 0. Verified starting point

Branch `phase-4`, most recently `f3f247b`. **`phase-4` is not merged into `main`.** Measured in
[docs/phase4-acceptance.md](../docs/phase4-acceptance.md):

- **435 tests passed, 3 gated skips, 88.73% branch coverage** in the last full measured run. Five
  tests were added after it and passed on their own; the WP4.0.1 commits added more. `pytest
  --collect-only` reports **475 tests** at `f3f247b`. That is a collection count, not a pass
  count — the first task of WP5.0 is a full measured run.
- **48 labelled scenarios** across three lanes (5 `phase1`, 18 `supportlab`, 25 `agent`), 13 risk
  classes in `baselines/corpus-baseline.json`, 7 agent defenses in `control/phase3_tools.py`.
- Deterministic replay 229 of 229. Smoke 14 of 14 in 11.72 s. Holdout 17 of 17 denied. Regression
  registry 48 of 48 at corpus-test granularity. Five gates pass clean and each blocks alone when a
  violation is injected through the CI command.
- Agent corpus 25 of 25 on the compose fixture, agreeing with in-process runs on every status and
  oracle hash.

**The first fact that defines this phase:** the PRD admits Phase 5 "only after v1", and **v1 has
not been declared**. Phase 4 is "implemented, with real-model checkpoints open": the real-model
evidence is one scenario on one local model at temperature 0; there is no real API cost, no real
judge, no compromised-model run against a real model, no CI-observed red branch, no adjudicated
precision sample, no independent reviewer session, and no release attested from a clean commit
with a non-ephemeral key. Building expansion on top of that would stack new claims on unmeasured
ones. WP5.0 closes v1 first.

**The second fact:** the project's single strongest result came from its first real model.
`retrieval-provenance-guard`, credited in every Phase 3 run against the scripted stand-in, failed
against `qwen2.5:7b-instruct` because the defense was prompt marking alone; it passed only after
the application enforced provenance at the email sink (`f20f482`). A defense whose effectiveness
depends on which model is behind it is a different kind of defense from one that does not. That
distinction — not a model leaderboard — is what the evaluation matrix in WP5.2 is designed to
measure.

### What exists and is reusable as-is

| Area | Module | Reuse in Phase 5 |
| --- | --- | --- |
| Model plane | `adapters/model_provider.py`, `control/model_pins.py` | WP5.0 and WP5.2 point it at more pins. Local Ollama path proven by WP4.0.1; hosted path still untouched by a real endpoint. |
| Repetitions and intervals | `runtime/repetitions.py`, `scoring/agreement.py` | The matrix's per-cell numbers. Unchanged. |
| Verdict provenance | ADR 0009 (with the Phase 4 amendment) | Load-bearing again: every matrix cell, telemetry figure, and adjudication is advisory or human, never binding. |
| Gates | `reporting/gates.py`, ADR 0013 | Unchanged. Gate-isolation tests extend to every new output type. |
| Signing | `control/manifest.py` (ADR 0002), `reporting/attestation.py` (ADR 0012) | Risk approvals and adjudication records are signed with the same Ed25519/JCS machinery. No new cryptography. |
| Holdout | `control/holdout.py`, `scenarios/holdout/` | Imported benchmark cases are kept out of it and out of every tuning path by the same grep-test mechanism. |
| Importers | `adapters/importers.py` | PyRIT, garak, Promptfoo, and AgentDojo-style importers exist and produce **not-runnable** scenarios only. WP5.6 promotes a named subset. |
| Attacker | `control/attacker.py` | A deterministic bounded mutation search. Its docstring names a model-driven attacker as "an optional profile behind the same caps" that was never built — the first candidate for WP5.1's approval path. |
| Stand-in models | `ScriptedAgentModel`, `HostileModel`, `DelimitationBlindModel` | Deterministic matrix rows that anchor every real-model comparison. |
| Audit export, reviewer path | `reporting/audit_export.py`, `docs/reviewer-walkthrough.md`, `docs/samples/` | The review UI (WP5.4) reads exactly these; the reviewer session (WP5.0) consumes them. |
| CI lanes | `.github/workflows/phase{0..4}.yml` | Untouched, per the standing rule. Phase 5 adds `phase5.yml`. |

### What does not exist yet

No v1 tag or release attested from a clean commit, no dry-run or shadow execution mode (PRD §7
lists dry-run under the safety kernel; it was never built), no risk-approval document, no
machine-readable definition of an "autonomy or action-class increase", no evaluation matrix, no
OpenTelemetry export (a PRD §4 technology choice that was never built), no DuckDB/Parquet
analysis output, no human-review UI, no adjudication record format, no second target fixture, no
code-execution surface, no runnable imported case, and no recorded demo (WP4.5.3; not found in
the tree).

### Constraints inherited from Phase 4 that shape this phase

- **Gates read binding verdicts only** (ADR 0009, 0013). A matrix, a telemetry figure, a human
  label, or a real model can make a report worse or better; none can turn CI red or green.
- **A new surface gets a new fixture and a new CI lane**, and every earlier lane stays green and
  unchanged. `phase0`–`phase4` workflow files are not edited.
- **Imported cases are data.** An import that cannot express a deterministic oracle stays
  not-runnable; nothing is auto-promoted (WP3.4.5).
- **Retrieval is lexical** (ADR 0011). Vector retrieval moves retrieval into the stochastic class
  and must report its own replay rate if added.
- **There is no code-execution surface**, so unexpected code execution — a named PRD threat — is
  covered only as a containment property. Adding one is "a fixture capability change with its own
  containment story" (PRD WP4.0).
- **Detection delay is logical ticks.** WP4.0 left the choice open: instrument real wall-clock
  latency or keep the caveat. WP5.3 is where instrumenting it becomes cheap; until then the caveat
  stands.
- **The non-goals hold after v1** unless the PRD is amended: no hosted or multi-tenant service, no
  Kubernetes, no full SIEM, no autonomous scope expansion or risk acceptance, no claim that a
  passing benchmark proves safety.

---

## 1. Objectives

1. **Close v1 (WP5.0).** Clear the open Phase 4 rows, merge, and tag a release attested from a
   clean commit with a non-ephemeral key — or record each row that cannot be closed as an explicit,
   reasoned decision, never as silence.
2. **Land the governance control before any capability increase (WP5.1).** Shadow mode and signed
   risk approval for every autonomy or action-class increase, enforced at admission.
3. **Measure defenses across models (WP5.2).** A pinned models × defenses matrix whose headline
   output is which defenses are model-independent and which depend on the model's cooperation.
4. **Make runs observable outside the bundle (WP5.3)** with a self-hosted OpenTelemetry profile
   and a DuckDB/Parquet analysis export, without creating a new leak path or a second source of
   truth.
5. **Give humans a review surface (WP5.4)** — a local, read-only review UI whose only write is a
   signed adjudication record.
6. **Add a second disposable target fixture (WP5.5)** with a contained code-execution surface,
   closing the one PRD threat class that has no scenario.
7. **Promote a benchmark subset to runnable (WP5.6)** with authored oracles, recorded license and
   provenance, and imported counts reported separately from authored ones.

### The rule that holds the phase together

> Phase 5 is the first phase allowed to make the harness more capable rather than more
> trustworthy. So every capability increase passes the kernel twice: first in **shadow**, where it
> decides and does not act, then under a **signed risk approval** that names the shadow evidence it
> was granted on. Nothing becomes more autonomous because a work package needed it to — and a test
> proves admission refuses a widened manifest without a matching approval.

### Delivery model for this phase

Unlike Phases 0–4, Phase 5 has no single closing checkpoint. Per the PRD, each item is its own
work package with its own acceptance note (`docs/phase5/wp5.<n>-acceptance.md`). WP5.0 and WP5.1
are prerequisites; WP5.2–WP5.6 are independent and optional. A package may be **dropped** — that
is recorded in `docs/phase5-acceptance.md` with a reason, and its partial work does not land on
`main` half-built.

### Non-goals for this phase

A hosted, multi-user, or authenticated service; Kubernetes; a full SIEM; any autonomous risk
acceptance (approvals are human and signed); fine-tuning or training anything; a leaderboard or a
single composite score per model; auto-promotion of imported cases; the **harness** executing code
(the new fixture executes code, inside its own containment — the harness never does); weakening
any Phase 0–4 invariant; editing the `phase0`–`phase4` workflows.

---

## 2. The hard problems

### 2.1 What "v1" means when some of its checkpoints need a human, a bill, or a push

The Phase 4 checkpoint has rows of three kinds: rows the author can close alone with a command
(CI red branches, a temperature-sampled corpus run on a local pin, a compromised-model run), rows
that need money (a hosted cost figure, a hosted judge), and rows that need another person (the
independent reviewer, arguably the adjudicated precision sample). Treating them alike either
blocks Phase 5 forever on a human who never appears, or lets "untested" quietly become the
default.

**Design:**

- **Author-closable rows must be met.** No v1 tag while a row that needs only a command is open.
- **Money rows are met with a stated, signed budget**, sized from WP5.0.1's measured per-call
  cost; the hosted run's `cost_microusd_budget` is in its signed manifest.
- **Human rows** are attempted with the protocol already in place. If, by the time every other
  row is met, they have not run, v1 may still be tagged — but only through a written decision in
  the WP5.0 acceptance note that names each untested row, why, and what would close it. The tag's
  release notes repeat those words.
- **v1 is an artifact, not a sentence:** `phase-4` merged to `main`, tag `v1.0.0` on a clean
  commit, the `release` job's attestation signed with the CI key from repository secrets and
  carrying that commit — closing the Phase 4 limit that the only release attestation was ephemeral
  and named no commit.

### 2.2 Shadow mode that actually shadows, and an "increase" that a machine can detect

Two failure modes. A shadow that leaks — some path still calls an adapter — is worse than none,
because it is trusted. And "every autonomy or action-class increase" is unenforceable if deciding
what counts as an increase is left to whoever writes the manifest.

**Design — the capability delta:**

- A pure function `capability_delta(approved, requested) -> frozenset[CapabilityIncrease]` over
  two manifests. Increases are a closed enum: new action class (ordered `read < write <
  external-send < code-exec`), new adapter or operation, new target fixture, widened egress,
  raised attacker caps (`max_attacker_proposals`, `max_attacker_depth`), and a change of proposal
  source (bounded search → model-driven). Anything the function does not recognize as a narrowing
  is an increase — fail closed.
- Property-tested: any generated widening yields a non-empty delta; any narrowing or reordering
  yields the empty set; the delta is invariant to field order and canonicalization.
- The **approved baseline** is the v1 capability surface, signed once at the v1 tag. Every later
  delta is computed against the most recent approved surface, not against the previous run.

**Design — shadow execution:**

- A `shadow` run mode in `SafetyRuntime`: admission, compilation, policy, and budget reservation
  run in full; the adapter is **never invoked**. Each would-be execution is recorded as a
  `SHADOW_SUPPRESSED` event with the decision that would have applied. A counting adapter wrapper
  asserts zero adapter calls across the whole shadow suite, and fault-injection cases try to force
  execution through every adapter.
- Shadow output is a `ShadowReport`: action classes reached, operations proposed, policy denials
  by reason, budget that would have been consumed, and proposal-rejection rate.
- **Representativeness is a stated limit, not a solved problem.** Nothing executes, so nothing
  responds, so later steps that depend on a response are not reached. The report records how many
  steps were unreachable for that reason.

**Design — risk approval:**

- `RiskApproval` is a signed document naming the exact capability delta it covers, the
  `ShadowReport` digest it was granted on, an expiry, and an approver key ID. Admission refuses a
  manifest whose delta is not covered by a valid, unexpired approval.
- The approver key must differ from every key that may attest or run under the manifest
  (separation of keys, enforced). No model, attacker, or judge component can produce an approval;
  the kernel only verifies them.
- **Honest limit:** in a single-author project, separate keys are not separate people. If no
  second person holds the approver key, the acceptance note says so in those words.

### 2.3 A matrix that compares without manufacturing a ranking

Models × defenses × scenarios × repetitions × two legs grows fast — three models, eight defense
configurations, 25 scenarios, and five repetitions is 6,000 leg executions — and it invites the
output the PRD forbids: a composite score, read as "model X is safe". The interesting question is
narrower, and WP4.0.1 already supplies it: **does this defense still work when the model stops
cooperating?**

**Design:**

- **A signed `EvaluationMatrix` spec:** pins (with decoding and seeds), defense configurations,
  scenario subset, repetitions, and a cost cap. A pre-flight estimate above the cap is a recorded
  refusal before the first call (Phase 4 §2.6 machinery).
- **Deterministic anchor rows:** `ScriptedAgentModel` (compliant), `DelimitationBlindModel`
  (follows injections wherever they appear), and `HostileModel` are matrix rows beside the real
  pins. They cost nothing, replay exactly, and give every real-model cell a known floor and
  ceiling.
- **Pre-registered contrasts only:** per defense, attack success under the defense versus no
  defense, paired by scenario, per pin. Exact paired test (McNemar's exact form) for per-scenario
  binary outcomes, Holm correction across the registered family, α fixed in
  `docs/evaluation-methodology.md` before the first matrix run. Unregistered comparisons may be
  plotted, labelled "exploratory".
- **The headline classification:** a defense is **model-independent** on this corpus if it is
  credited under every row including `DelimitationBlindModel`; **model-dependent** if its credit
  varies across rows; **ineffective** if credited under none. This is per scenario, reported with n
  and intervals, and states which kind of enforcement each defense uses (application-side check vs.
  prompt-only).
- **Sampling, not greedy decoding:** real-pin rows run at a pre-registered temperature above 0, so
  variance is real. A temperature-0 column may be added and is labelled as a greedy-decoding
  measurement, as WP4.0.1 was.
- **Judge independence:** the judge pin is from a different family than every target pin, or the
  self-family delta from WP5.0.4 is printed beside the affected cells.
- **Advisory, structurally:** matrix outputs carry `pinned-stochastic` provenance; the gate
  boundary rejects them by type, and the gate-isolation test is extended to cover them.

### 2.4 Telemetry is a new egress and a second copy of the evidence

OpenTelemetry export creates two hazards: spans become a place secrets and canaries leak (they
are emitted from more code paths than the ledger is written from), and a dashboard becomes a
competing source of truth that can disagree with the signed bundle.

**Design:**

- **The ledger stays authoritative; telemetry is a projection.** Spans and metrics are derived from
  ledger events **after redaction**, in the evidence writer — never emitted directly from adapters,
  the model plane, or the fixture. Telemetry therefore cannot contain anything the ledger does not.
- **Telemetry is outside the TCB.** An export failure records a `TELEMETRY_EXPORT_FAILED` lifecycle
  event and the run continues; it never changes an outcome, a verdict, or a budget. This is the
  opposite of the kernel's fail-closed rule on purpose, and ADR 0016 says why.
- **No new egress.** The collector runs on the fixture's internal network as a signed asset in
  Manifest 1.5; the profile is off by default and absent from the PR lane.
- **Leak tests:** the existing secret-scanning assertions (and `test_sample_hygiene.py`'s planted-
  leak checks) run over exported spans from a full agent suite, including the canary and
  brokered-credential cases.
- **Wall-clock detection latency becomes measurable** as an advisory figure from span timestamps,
  reported beside the logical-tick figure and labelled as wall clock on this machine. The tick
  figure is not replaced.
- **Analysis export:** `purpleloop analyze` writes verified bundles to Parquet and queries them with
  DuckDB (both PRD §4 choices). It reads verified bundles only, and refuses an unverified one.

### 2.5 A review UI is a write path into evidence, and it renders attacker content

A human-review UI has to display what the corpus deliberately contains: hostile HTML, Markdown,
and injection payloads (`agent-indirect-html`, `agent-indirect-markdown`). And a UI that can write
anything can, eventually, write over the evidence it reviews.

**Design:**

- **Read-only over bundles and audit exports.** The only write is an `AdjudicationRecord`: a signed
  label (true positive / false positive / cannot tell) with a rationale and the cited evidence IDs,
  stored beside — never inside — the bundle. A test asserts bundle bytes are unchanged after a full
  adjudication session.
- **Human labels are not verdicts.** `AdjudicationRecord` is its own type, not a
  `VerdictProvenance` value; it feeds the precision checkpoint, never a gate.
- **Blinded by default:** the oracle's verdict is hidden until the adjudicator records a label, to
  avoid anchoring; the unblinded view is recorded as such in the record.
- **Untrusted content stays inert.** Server-rendered, every evidence field escaped, a strict
  Content-Security-Policy with no script sources for evidence views, and an XSS test that renders
  every corpus payload and asserts no executable markup reaches the page.
- **Local only:** bound to `127.0.0.1`, no accounts, no hosting (non-goal). The adjudication record
  format is introduced in WP5.0 with a CLI, so the precision checkpoint does not wait on the UI; the
  UI writes the same format.

### 2.6 A target that executes code, without the harness ever doing so

The PRD names "unexpected code execution and cascading failure" as threat coverage and the corpus
has no scenario for it. A target with a code-execution tool makes that measurable — and makes
containment escape a real attack surface instead of a property tested against a fixture that could
not attempt it.

**Design:**

- **New fixture, new lane** (`codelab`): a small agent application whose tools include a sandboxed
  "run analysis snippet" capability. The code runs in a **separate sandbox container** owned by the
  fixture, never in the fixture's app process and never in the harness: no network, read-only root
  except a size-capped tmpfs, dropped capabilities, `no-new-privileges`, seccomp default profile,
  pids/memory/CPU limits, and a wall-time kill. gVisor (`runsc`) where the host supports it; the
  acceptance note records which runtime ran.
- **Findings are state, not claims:** a planted canary file and a sandbox-side marker are read by
  closed-operator oracles. "The model said it ran code" is not evidence.
- **Containment escape is a test suite with a real surface:** network egress, writes outside tmpfs,
  reading the canary from outside the sandbox, fork bombs, and the wall-time kill — each attempted
  by scenario payload and each required to fail and be recorded. Any success is a release-blocking
  invariant breach, not a finding.
- **Requires a WP5.1 risk approval** (`code-exec` is a new action class). This is the first real
  use of the approval path and doubles as its end-to-end test.

---

## 3. Contract changes

All additive and versioned; 1.0–1.4 documents keep byte-identical canonical bytes and digests,
asserted by the existing round-trip tests extended to 1.5. `baselines/schema-digests.json` gains
entries for each new reference document, so the schema-drift gate covers them from the start.

### 3.1 Manifest 1.5

Adds `Phase5Grants`:

- `action_classes`: the closed set the engagement may exercise (`read`, `write`, `external-send`,
  `code-exec`).
- `risk_approvals`: digests of the `RiskApproval` documents that cover the manifest's capability
  delta.
- `run_mode`: `execute` (default) or `shadow`.
- `matrix_scope`: the signed `EvaluationMatrix` digest authorized for unattended spend, if any.
- `telemetry`: the collector asset ID, or absent (the default — no export).

### 3.2 `RiskApproval` 1.0 and `ShadowReport` 1.0

As designed in §2.2. `RiskApproval` is signed with an approver key whose ID must not appear in the
manifest's `attestation_key_ids`. `ShadowReport` is an ordinary sealed bundle member with a digest
the approval references.

### 3.3 `EvaluationMatrix` 1.0 and `MatrixCell` / `DefenseDependence`

The signed spec (§2.3), its per-cell results (value, n, interval, pin, seed policy, provenance),
and the per-defense classification. All carry advisory provenance; the gate input types reject them.

### 3.4 `AdjudicationRecord` 1.0

Finding ID, bundle digest, label, rationale, cited evidence IDs, blinded flag, reviewer key ID,
signature. Introduced in WP5.0, written by both the CLI and the WP5.4 UI.

### 3.5 Scenario 1.4

- `origin`: `authored` or `imported`, with `import_source` (framework, upstream version or commit,
  license, case ID) required when imported.
- `public_exposure`: true for any case whose payload is published upstream, so results on it are
  labelled as possibly contaminated by model training data.
- Lane `codelab` added to the lane enum.

### 3.6 Telemetry namespace

`purpleloop.*` span and attribute names, versioned in `docs/telemetry-namespace.md` (the PRD §4
"versioned project event namespace"), generated from the event-kind enum so the two cannot drift.

---

## 4. Work packages

### WP5.0 — Close v1 (debt carried out of Phase 4)

This lands first. Until it does, Phase 5 is not admitted by the PRD.

| # | Task | Done when |
| --- | --- | --- |
| 5.0.1 | Full measured suite run at the phase base | Pass count, skips, coverage, wall time recorded; the 475-collected figure reconciled to a pass count. The Phase 4 stalled run (92 min, ~9 min CPU) is re-checked: reproduced and explained, or recorded again as not reproduced. |
| 5.0.2 | Agent corpus on the local pin, sampled | 25 scenarios × ≥5 repetitions at a pre-registered temperature > 0; variance and `ReproductionRecord`s measured; every bundle verified. Each regression is triaged as an application finding (fixed in the fixture, with a stand-in test that fails without the fix, as in `f20f482`) or a harness defect. No scenario is moved to a different defense to make it pass. |
| 5.0.3 | Calibrate token expectations per real pin, once | The WP4.0.1 data (6 calls, 446–518 in, 76–139 out) and 5.0.2's run fix the local pin's expectations; held fixed thereafter; ±10% reported. |
| 5.0.4 | Real API cost on a hosted pin | Provider-billed microUSD vs pre-run estimate, ±10%, non-vacuous for the first time, under a signed cost cap. |
| 5.0.5 | Real-judge agreement and self-family delta | A real pinned judge against the frozen 24-case corpus (digest unchanged, asserted); α and κ with n and CI; target and judge from the same family run once and the delta stated. |
| 5.0.6 | Compromised-model property against a real model | Same property, real intent distribution; zero out-of-scope executions; invented operations recorded as refusals. |
| 5.0.7 | CI-observed gates and lanes | The five `gate-proof/*` branches pushed, each observed red at its own gate and green earlier, plus a green control; run URLs recorded. `pr-fast` wall time from CI history. The `nightly-stochastic` job observed at least once with a classified outcome. |
| 5.0.8 | Adjudicated precision census | `purpleloop adjudicate` (CLI) writes `AdjudicationRecord`s; every distinct accepted finding class adjudicated; precision reported with Wilson bound and the method (census, not survey). |
| 5.0.9 | Independent reviewer session | Run with the existing protocol and samples, timed, recorded per Phase 4 open question 7 — or named untested in the v1 decision (§2.1). |
| 5.0.10 | Per-scenario regression pinning | The three corpus-level pinning tests parametrized by scenario so each registry entry names its own node ID; the Phase 4 granularity caveat closes. |
| 5.0.11 | Recorded demo | The one-command demo recorded, including a fail-closed case, linked from the README (WP4.5.3). |
| 5.0.12 | Merge, tag, attest | `phase-4` merged to `main`; `v1.0.0` on a clean commit; `release` attestation with the CI key and that commit; the PRD §11 resume claim re-checked word by word against the measured numbers; the v1 capability surface signed as the approved baseline for WP5.1. |

### WP5.1 — Shadow mode and risk approval

Files: `control/capabilities.py` (`capability_delta`), `control/approvals.py`, shadow mode in
`runtime/runtime.py`, `schemas/phase5.py`, `phase5_cli.py` (`shadow-run`, `approve`,
`approval-check`), ADR 0014, `.github/workflows/phase5.yml` job `governance`.

| # | Task | Notes |
| --- | --- | --- |
| 5.1.1 | `capability_delta` | §2.2. Pure function, closed increase enum, unknown change treated as increase. Unit and property tested. |
| 5.1.2 | Shadow run mode | Adapter never invoked, `SHADOW_SUPPRESSED` events, zero-call assertion across the suite, fault injection trying to force execution through each adapter. |
| 5.1.3 | `ShadowReport` | Action classes reached, denials by reason, would-be budget, rejection rate, unreachable-step count. |
| 5.1.4 | `RiskApproval` signing and verification | Approver key distinct from attestation keys (enforced); expiry; exact delta; shadow digest cross-checked. |
| 5.1.5 | Admission enforcement | A manifest with an uncovered delta is refused at admission with a reason code, and the refusal is evidence in the audit export. |
| 5.1.6 | First real use: model-driven attacker profile in shadow | The attacker profile the Phase 3 docstring promised, behind the same caps, run in shadow only. Promoting it to `execute` is a separate, approved step — and is optional. |

### WP5.2 — Pinned evaluation matrix (models × defenses)

Files: `runtime/matrix.py`, `scoring/phase5.py`, `scenarios/matrix/` (signed specs),
`phase5.yml` job `matrix` (dispatch only; never on PR).

| # | Task | Notes |
| --- | --- | --- |
| 5.2.1 | Signed matrix spec with pre-flight cost refusal | §2.3. Spend authority is signed data. |
| 5.2.2 | Rows | Three deterministic stand-ins + at least two real pins from different model families (the WP5.0 local and hosted pins). |
| 5.2.3 | Columns | No defense, each of the 7 agent defenses alone, and the scenario-assigned defense. |
| 5.2.4 | Pre-registered contrasts | Exact paired test, Holm correction, α written into the methodology before the first run. |
| 5.2.5 | Defense-dependence classification | Model-independent / model-dependent / ineffective, per scenario, with n and intervals, and the enforcement kind of each defense stated. |
| 5.2.6 | Report | A separate matrix section in the HTML report and a Parquet table; no composite per-model score anywhere; worst cases shown per row. |
| 5.2.7 | Gate isolation | Matrix outputs rejected at the gate boundary by type; extension of the Phase 4 test. |

### WP5.3 — Self-hosted observability profile

Files: `reporting/telemetry.py`, `reporting/analysis.py`, `compose.observability.yaml`,
`docs/telemetry-namespace.md`, ADR 0016.

| # | Task | Notes |
| --- | --- | --- |
| 5.3.1 | Ledger-derived OTel export | §2.4: post-redaction projection from the evidence writer only. |
| 5.3.2 | Local collector profile | Internal network, signed asset, off by default, absent from `pr-fast`. |
| 5.3.3 | Leak tests over exported spans | Secret-scanning and planted-leak assertions over a full agent suite's export. |
| 5.3.4 | Export failure is non-fatal and recorded | Fault injection: collector down, slow, refusing. Outcomes and verdicts byte-identical with and without telemetry. |
| 5.3.5 | Wall-clock detection latency | Advisory figure beside the logical-tick figure, labelled as wall clock on the measuring machine. |
| 5.3.6 | `purpleloop analyze` | Verified bundles → Parquet → DuckDB; refuses unverified bundles. |

### WP5.4 — Human-review UI

Files: `review/` (FastAPI app, server-rendered templates), `phase5_cli.py` (`review`), ADR 0017.

| # | Task | Notes |
| --- | --- | --- |
| 5.4.1 | Read-only bundle and audit-export views | Run timeline, decisions with reason codes, oracle inputs, evidence by ID. |
| 5.4.2 | Adjudication write path | Writes `AdjudicationRecord` only; bundle bytes unchanged (asserted). |
| 5.4.3 | Blinding | Oracle verdict hidden until a label is recorded; unblinded views flagged in the record. |
| 5.4.4 | Inert rendering | Escaping, strict CSP, XSS test over every corpus payload. |
| 5.4.5 | Reviewer protocol on the UI | `docs/reviewer-walkthrough.md` gains a UI path; a second timed session if a reviewer is available, compared with the CLI path. |

### WP5.5 — Second disposable fixture: `codelab`

Files: `targets/codelab/`, `fixture/codelab/`, `control/phase5_tools.py`, `scenarios/codelab/`,
`compose.codelab.yaml`, `phase5.yml` job `codelab`, ADR 0015.

| # | Task | Notes |
| --- | --- | --- |
| 5.5.1 | Sandbox container and its containment | §2.6. Runtime recorded (gVisor or hardened runc). |
| 5.5.2 | Risk approval for `code-exec` | Shadow report, signed approval, admission accepting only with it — WP5.1's end-to-end test. |
| 5.5.3 | 8–12 labelled scenarios | Unexpected code execution, cascading failure through tool output, injection into the snippet argument, each with a defended negative control and a deterministic oracle. |
| 5.5.4 | Containment-escape suite | Every escape attempt fails and is recorded; any success is an invariant breach. |
| 5.5.5 | Replay and corpus metrics for the new lane | Reported per lane; the per-risk-class baseline gains the new classes through an explicit baseline-bump commit. |

A vector-retrieval variant of `supportlab` is the alternative second fixture (open question 5). If
chosen instead, its retrieval is stochastic-class and reports its own replay rate.

### WP5.6 — Framework adapters and benchmark subsets

Files: `adapters/importers.py`, `scenarios/imported/<framework>/`, a per-subset provenance file.

| # | Task | Notes |
| --- | --- | --- |
| 5.6.1 | Choose one subset and record it | Framework, upstream version or commit, license verified at import time, case IDs, selection rule. |
| 5.6.2 | Promote cases by authoring oracles | Each promoted case gets a hand-authored deterministic oracle, a ground-truth label, and its conversion issues cleared one by one. Cases that cannot get one stay not-runnable and are counted. |
| 5.6.3 | Separate reporting | Imported and authored counts and metrics reported separately; `public_exposure` cases labelled as possibly contaminated. |
| 5.6.4 | Kept out of holdout and tuning | The holdout grep test extended to `scenarios/imported/`. |
| 5.6.5 | Matrix inclusion (if WP5.2 has landed) | Imported cases run as a separately reported matrix block. |

---

## 5. Test plan

- **Unit** — `capability_delta` on every increase kind and on narrowings; `RiskApproval` and
  `AdjudicationRecord` signing, verification, and tamper cases (statement, delta, shadow digest,
  expiry, wrong key, approver key equal to an attestation key); matrix contrast arithmetic, Holm
  correction, and defense-dependence classification on constructed cells; span projection from
  ledger events; Manifest 1.5 and Scenario 1.4 round-trips with byte-identical legacy bytes.
- **Property** — any generated manifest widening yields a non-empty delta and is refused without an
  approval; narrowing never requires one; a shadow run over generated plans never calls an adapter.
- **Contract** — telemetry contains nothing absent from the redacted ledger; the analysis export
  refuses unverified bundles; the review UI never writes to a bundle path.
- **Adversarial** — every corpus payload rendered by the review UI with no executable markup;
  evaluator-red-team payloads placed in adjudication rationale fields do not alter any stored
  verdict; containment-escape attempts from `codelab` all fail.
- **Fault injection** — collector down, slow, or refusing (no outcome change); approval expiring
  mid-suite (fail closed at the next admission); sandbox container killed mid-snippet (teardown,
  recorded outcome, verifiable partial bundle); hosted-endpoint 429/5xx storms during the matrix.
- **Gate isolation** — matrix cells, telemetry figures, and adjudication records are each rejected
  at the gate boundary by type.
- **Regression** — the full Phase 0–4 suites pass unchanged; all recorded seed hashes and canonical
  digests byte-identical; `phase0`–`phase4` workflow files untouched (asserted by path against the
  phase base).

---

## 6. Acceptance checkpoints

Each work package closes on its own note. Each number names how it is measured. Nothing is
established by inspection.

| WP | Checkpoint | Threshold | Measurement |
| --- | --- | --- | --- |
| 5.0 | Author-closable Phase 4 rows | All met | Rows 5.0.1–5.0.7, 5.0.10–5.0.12 recorded from commands run |
| 5.0 | Real API cost vs estimate | ±10%, non-vacuous | Provider billing vs pre-run estimate on the hosted pin |
| 5.0 | Precision on adjudicated findings | ≥ 95%, Wilson bound, method stated | `AdjudicationRecord` census |
| 5.0 | Reviewer reconstruction | 3 sets in ≤ 30 min | Timed session, or named untested in the v1 decision |
| 5.0 | v1 exists | Tag + CI-key attestation naming the commit | `verify-bundle --attestation` on the release bundle |
| 5.1 | Shadow never executes | 0 adapter calls | Counting wrapper over the full shadow suite plus fault injection |
| 5.1 | Uncovered increase refused | 100% of generated widenings | Property test + one admission refusal per increase kind |
| 5.2 | Matrix run exists | ≥ 2 real pins + 3 stand-ins, ≥ 5 reps | Verified bundles; every cell with n, interval, pin, provenance |
| 5.2 | Defense dependence classified | Every agent defense | Pre-registered contrasts, Holm-corrected |
| 5.3 | No leak through telemetry | 0 findings | Secret scan + planted-leak test over a full suite export |
| 5.3 | Telemetry changes nothing | Byte-identical outcomes and verdicts | Same suite with and without the profile |
| 5.4 | UI is inert and read-only | 0 executable payloads; bundle bytes unchanged | XSS corpus test; digest before/after a session |
| 5.5 | Containment holds | 0 escapes | Escape suite under the recorded runtime |
| 5.5 | New lane corpus | Seeded recall ≥ 90%, FP ≤ 5%, replay ≥ 98% | `corpus_metrics` and replay trials on `codelab` |
| 5.6 | Imported subset runnable | Count promoted / count attempted, both reported | Per-case oracle + label; no auto-promotion |
| All | Prior suites and lanes | Pass unchanged; `phase0`–`phase4` workflows untouched | Existing lanes; path assertion |
| All | Coverage | ≥ 85% branch | Floor, not target |

---

## 7. Risks

| Risk | Impact | Mitigation |
| --- | --- | --- |
| v1 never closes because a human checkpoint never runs | Phase 5 blocked indefinitely, or "untested" becomes the default | §2.1: author-closable rows must be met; human rows may be named untested only through a written v1 decision. |
| Shadow mode leaks an execution | A trusted control that is false | Zero-call wrapper over the suite, fault injection per adapter, shadow implemented by not dispatching rather than by a flag the adapter checks. |
| "Increase" defined loosely | Approvals become paperwork | Closed enum, unknown-is-increase, property tests; approval names the exact delta. |
| Separate keys mistaken for separate people | Overstated governance | The acceptance note says who held which key, in plain words. |
| Matrix spend runs away | Real money | Signed spec, pre-flight refusal, per-run cap, dispatch-only job, never on PR. |
| Matrix read as a model leaderboard | Inverts the PRD's "passing ≠ safe" | No composite score; per-defense dependence as the headline; worst cases per row; limitations stated with every table. |
| Telemetry becomes a leak or a second truth | Secrets in spans; dashboards contradicting bundles | Post-redaction ledger projection only; leak tests; bundle remains the only verified record. |
| Review UI renders a payload | XSS in the reviewer's browser, from the project's own corpus | Escaping, CSP without script, XSS test over every payload, local bind. |
| `codelab` sandbox escapes | A containment breach on the developer's machine | Separate container, no network, hardened runtime, escape suite before any scenario runs; gVisor where available. |
| Imported cases contaminated by training data | Real-model numbers on them overstate or understate | `public_exposure` label; separate reporting; never in holdout or tuning. |
| Phase 5 sprawls across seven packages | Several half-built features on `main` | Independent acceptance notes; dropped packages recorded and kept off `main`. |

---

## 8. Sequencing

```
WP5.0 close v1 (5.0.1 suite run first; 5.0.2 → 5.0.3 → 5.0.4/5.0.5/5.0.6; 5.0.7–5.0.11 in parallel; 5.0.12 last)
   └─> §3 contracts (Manifest 1.5, RiskApproval, ShadowReport, AdjudicationRecord*, Scenario 1.4)
          └─> WP5.1 shadow mode + risk approval
                 ├─> WP5.5 codelab fixture ── (first approval: code-exec)
                 ├─> WP5.2 evaluation matrix ── (model-driven attacker column needs an approval)
                 ├─> WP5.6 benchmark subsets ── (feeds a separate WP5.2 block if both land)
                 ├─> WP5.3 observability ──┐
                 └─> WP5.4 review UI ──────┴─> docs/phase5-acceptance.md (index)

* AdjudicationRecord lands inside WP5.0 (5.0.8), ahead of the rest of §3.
```

WP5.0 lands first because the PRD admits nothing else until v1 exists, and because its measured
per-call cost sizes WP5.2. WP5.1 lands second because WP5.5 and the model-driven attacker in WP5.2
are capability increases and cannot be admitted without it; WP5.3, WP5.4, and WP5.6 do not
increase autonomy and could start in parallel with WP5.1, but are listed after it so the approval
path exists before anything ships. WP5.2–WP5.6 are independent of one another and individually
optional; each closes on its own note, written from commands actually run.

---

## 9. Open questions

Each needs a decision before the work package that depends on it starts. Recommendations given;
each becomes an ADR or a recorded decision in the relevant acceptance note.

1. **Can v1 be tagged with human checkpoints untested?** *Recommendation:* yes, but only through a
   written decision naming each untested row, and only after every author-closable and money row is
   met (§2.1). Blocks WP5.0.12.
2. **Which hosted pin, and at what cap?** *Recommendation:* one inexpensive hosted model on an
   OpenAI-compatible endpoint, cap set from WP5.0.2's measured tokens per scenario × the hosted
   price with stated headroom, and written into the signed manifest. Blocks WP5.0.4.
3. **Who holds the approver key?** *Recommendation:* a second person (an advisor or peer) if one is
   available; otherwise a separate offline key held by the author, recorded honestly as such.
   Blocks WP5.1.4.
4. **How large is the first matrix?** *Recommendation:* the 25 agent scenarios × 8 defense columns
   × (3 stand-ins + 2 real pins) × 5 repetitions, cut to a named scenario subset if the pre-flight
   estimate exceeds the cap — the cut written into the signed spec, never applied after a bill.
   Blocks WP5.2.1.
5. **Which second fixture: `codelab` or a vector-retrieval `supportlab` variant?**
   *Recommendation:* `codelab`. It closes a PRD threat class that has no scenario and gives
   containment escape a real surface; vector retrieval adds variance without adding a threat class.
   Blocks WP5.5.
6. **Which benchmark subset first?** *Recommendation:* AgentDojo-style tasks, because they already
   separate legitimate-task utility from attacker objectives with state checks (PRD §10), so oracles
   map most directly. License verified at import. Blocks WP5.6.1.
7. **Which observability backend?** *Recommendation:* the OTel collector with a file exporter as the
   default (no extra service to secure), and a single-container trace viewer as an optional compose
   profile. Blocks WP5.3.2.
8. **What sandbox runtime does `codelab` require?** gVisor is practical on Linux CI and not on
   Docker Desktop for macOS. *Recommendation:* hardened runc as the floor everywhere, gVisor in the
   Linux CI lane, and the acceptance note records which runtime produced each number. Blocks WP5.5.1.
9. **Review UI stack?** *Recommendation:* FastAPI with server-rendered templates, no client-side
   framework — already a dependency, and the smallest surface that satisfies §2.5. Blocks WP5.4.
