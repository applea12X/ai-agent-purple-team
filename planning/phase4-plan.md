# Phase 4 implementation plan — CI quality system and portfolio release

**Status: implemented (2026-09-15), with the real-model work packages open.** This working plan
is superseded by the as-built design note [docs/phase4-plan.md](../docs/phase4-plan.md) and the
measured record in [docs/phase4-acceptance.md](../docs/phase4-acceptance.md); it is retained
for its rationale. Section 8, Phase 4 of [PRD.md](PRD.md) is authoritative; where this document
and the PRD disagree, the PRD wins. WP4.0's real-endpoint items (a real stochastic run, real
cost, a real judge, the compromised-model property against a real model) and the CI-observed
red-branch runs remain open until a real pinned endpoint and pushed branches exist; the
acceptance record lists them explicitly.

---

## 0. Verified starting point

Branch `phase3`, most recently `fa2b3e2`. Measured in
[docs/phase3-acceptance.md](../docs/phase3-acceptance.md):

- **339 tests passed, 3 gated skips, 88.53% branch coverage** against the 85% floor. Phase 0/1's
  133 and Phase 2's 37 pass unchanged.
- **48 labelled scenarios** across three lanes (5 `phase1`, 18 `supportlab`, 25 `agent`), all with
  versioned taxonomy mappings, complete ground-truth labels, and deterministic oracles. All nine
  injection channels populated, checked by a test.
- Seeded recall 1.0, false positives 0, evidence completeness 1.0, agent-lane replay 75/75, judge
  metrics all at ceiling against the frozen 24-case evaluator-red-team corpus.
- Container lane: 9 container-gated tests pass; the 18-scenario Phase 2 demo verifies on
  PostgreSQL and Chromium; the agent corpus passes 25/25 on PostgreSQL with oracle hashes
  identical to SQLite.

**The one fact that defines this phase:** *no real model has ever been called.* Every Phase 3
number came from `ScriptedAgentModel` and `ScriptedJudge` — deterministic stand-ins. The
stochastic lane (`make agent-stochastic`, the nightly `stochastic` CI job,
`OpenAICompatibleProvider`, the pin/decoding/seed plumbing) exists, is tested against a stub
transport at 100% branch coverage, and has never touched a real endpoint. Phase 4 is where the
harness's claims about models stop being claims about a simulator.

### What exists and is reusable as-is

| Area | Module | Reuse in Phase 4 |
| --- | --- | --- |
| Real-model provider | `adapters/model_provider.py` (`OpenAICompatibleProvider`) | The nightly lane points it at a real endpoint. No code change expected for the happy path; real-endpoint behaviour (latency, 429s, partial responses) is where change may be forced. |
| Model-plane authorization | `runtime` (`SafetyRuntime.authorize_model`), `control/model_pins.py` | Unchanged. Runtime path is now test-covered after the Phase 3 audit; the nightly lane exercises it against real DNS and TLS. |
| Budgets | `control/budgets.py` | Unchanged. Token and cost fields become real money for the first time; hard caps and budget outcomes already exist. |
| Repetitions and CIs | WP3.6 machinery (`RepetitionSet`, Wilson/bootstrap intervals) | Unchanged. The nightly lane is its first consumer with genuinely varying trials. |
| Verdict provenance | `VerdictProvenance` (ADR 0009) | Load-bearing: it is the mechanism that lets real-model results into reports while keeping them out of gates. Every Phase 4 gate reads `deterministic` only, same as Phase 3. |
| Judge + frozen labels | `scoring/judge.py`, frozen 24-case corpus (digest `9bcf0a2f…`) | The label set and negative control are in place; WP4.0 points a real pinned judge at them. |
| Compromised-model property test | `tests/phase3/test_compromised_model.py` | The property re-runs with a real model as the intent source (WP4.0). |
| Manifest signatures | `control/manifest.py` (ADR 0002) | The signing machinery is the starting point for run attestations (WP4.3). |
| Evidence bundle | `reporting/bundle.py` (`verify-bundle`) | Extended with the attestation; the offline-verifiable sample bundle in WP4.5 is an ordinary bundle. |
| Corpus metric | `scoring/phase1.py` (`corpus_metrics`) | Unchanged; the per-risk-class regression gate (WP4.4) is computed from its per-scenario records. |
| CI lanes | `.github/workflows/phase{0..3}.yml` | Untouched, per the standing rule. Phase 4 adds `phase4.yml`; the existing `phase3.yml` stochastic job is superseded by the WP4.2 nightly lane, not edited away. |

### What does not exist yet

No measured result from a real model endpoint, no real API cost figure, no measured stochastic
variance or reproduction rate, no real-judge agreement number, no compose stack for the agent
lane, no run attestation format, no regression registry, no held-out mutation set, no retention
policy or audit export, no incident runbook, no enforcing per-risk-class regression gate, no
consolidated fast PR lane, no recorded demo, and no reviewer-verifiable sample bundle shipped in
the repository.

### Constraints inherited from Phase 3 that shape this phase

- **Stochastic results are advisory and gate nothing** (ADR 0009). Phase 4 adds real-model
  numbers and *five new enforcing gates* at the same time; the gates must be fed exclusively by
  deterministic verdicts, or the phase's two halves contradict each other. This is restated as a
  design rule in §2.1 and enforced by the existing gate-isolation tests extended to every new gate.
- The offline provider stays the default and the CI-PR default. A missing credential skips the
  lane and records the skip; there is no fallback path, and a test asserts none exists.
- Detection delay is injected logical ticks. Real token counts and real dollars arriving in the
  same report must not make the tick number look real by proximity (WP4.0, small items).
- `ModelClient` is deliberately not plan-reachable (ADR 0008); its contract behaviour is covered
  by dedicated tests. Phase 4 does not revisit the two-plane split.
- The per-call token expectations on the offline pin (187 in / 27 out) are calibrated for the
  *scripted* model. A real pin gets its own one-time calibration, then holds it fixed — the same
  discipline, per pin (WP4.0).
- `supportlab` has no code-execution surface, and Phase 4 does not add one. Unexpected code
  execution stays a containment property.
- Retrieval is lexical (ADR 0011) and stays lexical. Vector retrieval would move retrieval into
  the stochastic class and belongs in Phase 5, if anywhere.

---

## 1. Objectives

1. **Make the model-facing numbers real.** Run the stochastic lane, the judge-agreement
   measurement, the compromised-model property, and the token/cost checkpoint against at least one
   real pinned model endpoint, and report measured variance and reproduction rate as the stochastic
   lane's own numbers.
2. **Split CI into three lanes with distinct contracts:** a fast deterministic PR lane with a
   stated wall-time target, a nightly/manual real-model lane with ≥5 repetitions and confidence
   intervals, and a release lane that produces signed attestations and audit exports.
3. **Turn the checkpoint discipline into enforcement.** Five gate classes — scope bypass, critical
   regression, schema drift, budget failure, statistically meaningful per-risk-class regression —
   each specified, unit-tested, and *proven to block* by a deliberately failing branch per class.
4. **Build the release machinery:** run attestations in an in-toto/SLSA-shaped purpose-built
   format, a regression registry mapping every accepted finding to a test, a held-out mutation set
   kept out of the tuning loop, a retention policy, an audit export, and an incident runbook.
5. **Ship the portfolio release:** README with the one-command demo, architecture diagrams, a
   recorded demo, a sample evidence bundle a reviewer can verify offline, the benchmark
   methodology, and a results narrative that carries its uncertainty and limitations — validated
   by the independent-reviewer checkpoint, measured with an actual reviewer or reported untested.
6. Do all of the above without weakening a Phase 0–3 invariant and without editing the four
   existing CI lanes.

### The rule that holds the phase together

> Phase 4 adds the project's first real-model numbers and its first enforcing CI gates
> **simultaneously**, and they must never meet. Gates read deterministic verdicts only. A real
> model can make a report worse; it can never make CI red — and a test proves it, per gate.

### Non-goals for this phase

New attack surfaces, new adapters, new fixtures, or corpus growth beyond replacing weak cases
(the 48 stand); a code-execution surface; vector retrieval; model-vs-model comparison matrices;
a human-review UI; Kubernetes or hosted anything; any claim that a passing benchmark proves a
model or application safe. The `phase0`–`phase3` workflows are not edited.

---

## 2. The hard problems

### 2.1 First contact with a real endpoint, without contaminating the gates

Every number in the project is currently reproducible on demand. The first real-model run breaks
that for one lane, permanently and on purpose. The failure mode is not the variance itself — it is
*variance leaking into places built for determinism*: a flaky nightly job whose failures get
tolerated, a stochastic figure quoted next to a deterministic one without its n, or a gate that
quietly reads an advisory field because a new gate was wired in a hurry.

**Design:**

- The nightly lane has its own outcome vocabulary: `pass`, `fail`, `budget-stop`, `skip
  (no credential)`, `endpoint-error` — each recorded, each surfaced, none silently tolerated
  (PRD WP4.2: "a failure is surfaced, never silently tolerated"). An `endpoint-error` (DNS, TLS,
  429-exhaustion, provider outage) is a distinct class from a scenario failure, exactly as
  image-build failures were separated from evaluation failures in WP2.0.
- Reproduction rate is the stochastic lane's replay number: same pin, same seeds, same budget,
  re-run; report the fraction of repetitions reaching the same deterministic security verdict,
  with the reason for any gap stated. It sits beside — never inside — the deterministic lanes'
  replay figure, the way the browser lane's number already does.
- Every new gate added in WP4.4 gets the §2.1-Phase-3 gate-isolation test extended to it: a
  summary where an advisory verdict disagrees with the deterministic oracle leaves the gate's
  decision unchanged, and an advisory value placed in the gate's input path is rejected at the
  type boundary.

### 2.2 Proving the gates block, not asserting they would

The PRD checkpoint is explicit: "CI demonstrably blocks each of the five classes in WP4.4, proven
by a deliberately failing branch per class." A gate that has never fired is exactly as trustworthy
as a metric that cannot fail, and this project's standing rule is that every metric ships with a
test that fails when the metric is faked.

**Design — the red-branch protocol:**

- For each gate class, a branch (`gate-proof/scope-bypass`, `gate-proof/critical-regression`,
  `gate-proof/schema-drift`, `gate-proof/budget-failure`, `gate-proof/risk-class-regression`)
  carries one minimal, deliberate violation. Each branch is pushed, its CI run observed **red at
  the intended gate and green everywhere earlier** (so the failure is attributable), and the run
  URL plus the failing job's output recorded in `docs/phase4-acceptance.md`.
- The violations are seeded through test-only knobs where possible (an env var the gate job reads,
  a fixture manifest with a widened scope) rather than by corrupting production code, so each
  red branch is one commit and obviously artificial.
- Additionally, each gate's *decision function* is a pure, unit-tested function
  (`reporting/gates.py`): inputs are typed summaries, output is a typed gate decision with a
  reason. CI calls the same function the tests call. The red branch proves the wiring; the unit
  tests prove the logic; neither substitutes for the other.

### 2.3 A "statistically meaningful per-risk-class regression" needs an actual definition

The PRD requires the regression test and threshold to be "specified and unit-tested, not left to
judgment at review time." The trap is a gate that is either noise-triggered (blocking PRs on
deterministic-lane changes that are real but benign) or vacuous (a threshold so wide nothing
trips it).

**Design:**

- The gate compares **deterministic per-risk-class corpus metrics** (recall, false-positive
  count, executed-unauthorized-side-effect count per risk class) between the PR head and a
  recorded baseline (`artifacts/baselines/corpus-baseline.json`, versioned in the repo and
  updated only by an explicit, reviewed baseline-bump commit).
- Because the inputs are deterministic, "statistical" enters only where counts are small: the
  gate uses a two-proportion test (Fisher's exact, given class sizes of 5–25 scenarios) at a
  pre-registered α, **plus** an absolute floor — any newly missed seeded true positive in any
  risk class blocks regardless of p-value, because with deterministic verdicts a lost detection
  is a fact, not a sample. The statistical form exists for the nightly lane's advisory trend
  report, where repetition variance is real; there it *reports*, never blocks (§2.1).
- The exact test, α, floor, and baseline-update procedure are written in
  `docs/evaluation-methodology.md` and unit-tested with constructed cases on both sides of the
  threshold: a one-scenario recall loss blocks; an added scenario changing denominators does not;
  a baseline bump with the required marker is accepted.

### 2.4 An attestation format that is honest about its trust model

"In-toto/SLSA-shaped purpose-built format" invites two failure modes: inventing crypto, or
shipping a signature that attests nothing (signed by a key that lives next to the thing it
signs, over a statement no verifier checks).

**Design:**

- The attestation is a typed statement — subject (bundle digest), materials (code commit, lockfile
  digest, scenario corpus digest, manifest digest, model pins), builder (CI run ID or local),
  byproducts (test counts, coverage, gate decisions) — serialized through the existing JCS
  canonicalization path and signed with the **existing Ed25519 manifest-signature machinery**
  (ADR 0002). No new cryptographic constructions.
- `verify-bundle` gains `--attestation`: it verifies the signature, re-computes the subject digest
  from the bundle it sits beside, and checks the materials against the working tree when run
  inside the repo. A reviewer can do this offline with the public key shipped in the repo.
- The trust claim is stated in the ADR and the docs at exactly its real strength: the attestation
  binds *this bundle* to *this code, corpus, and configuration* under *this key*. It is
  tamper-evidence and provenance, not SLSA certification, and the docs say so — framework
  alignment is not certification (PRD §10).

### 2.5 The independent-reviewer checkpoint involves a human

"An independent reviewer reconstructs a passing run, a denied run, and an incident from exported
artifacts within 30 minutes" is the only checkpoint in the project that cannot be a pytest. The
standing rule applies: it is measured with an actual reviewer, or reported as untested — never
asserted from the author's own familiarity.

**Design:**

- Build the reviewer path first as a written protocol (`docs/reviewer-walkthrough.md`): what to
  download, what commands to run (`verify-bundle`, the audit export reader), what three questions
  to answer for each of the three artifact sets (what was attempted, what was decided and why,
  what evidence proves it).
- Produce the three artifact sets as fixed, committed samples: a passing paired run, a run denied
  at admission (expired manifest), and an evidence-integrity incident (from the existing
  fault-injection machinery).
- Recruit one reviewer who has not worked on the project; time the session; record duration,
  points of confusion, and whether each question was answered correctly, in the acceptance record.
  If no reviewer is available by acceptance time, the checkpoint is recorded **untested** in
  exactly those words, with the protocol and samples in place so it can be run later.

### 2.6 Real money, unattended

The nightly lane spends real API dollars with nobody watching. 48 scenarios × 2 legs × 5
repetitions × real calls, nightly, is the point where a retry loop or a mispriced pin becomes a
bill.

**Design:**

- The signed manifest for the nightly lane carries a hard per-run `cost_microusd_budget`; breach
  terminates fail-closed as a **budget outcome** (existing machinery). On top of that, the
  workflow itself carries a defense-in-depth wall-time timeout and the pre-run cost estimate is
  compared to the manifest cap *before the first call* — an estimate exceeding the cap is a
  recorded pre-flight refusal, not a mid-run stop.
- Nightly scope is a named subset if the full corpus is too expensive: the subset is chosen once,
  recorded, and rotated on a schedule written in the workflow file — never silently narrowed
  after a large bill. Reduced n is reported beside every affected figure, per the Phase 3 rule.
- The first real-pin calibration run (WP4.0) doubles as the cost measurement that fixes the
  nightly scope and repetition count, replacing guesswork with a measured per-scenario cost.

---

## 3. Contract changes

All additive and versioned; Phase 0–3 documents keep byte-identical canonical bytes and digests,
asserted by the existing round-trip tests extended to 1.4.

### 3.1 `RunAttestation` (new document, version 1.0)

As designed in §2.4: typed statement, JCS canonical bytes, Ed25519 signature, verified by
`verify-bundle --attestation`. Lives beside the bundle it attests, referenced by digest in the
bundle inventory so the bundle and attestation cross-bind.

### 3.2 Manifest 1.4

Adds `Phase4Grants`:

- `attestation_key_id`: which signing key attests runs under this engagement.
- `retention`: evidence retention class and duration per artifact kind (raw ledgers, bundles,
  screenshots/traces, model transcripts), consumed by the audit-export and retention tooling.
- `nightly_scope`: the named scenario subset and repetition count authorized for unattended runs,
  so the nightly lane's spend authority is signed data, not workflow configuration.

### 3.3 Stochastic outcome and trend records

- `StochasticRunOutcome`: the closed nightly-lane outcome enum from §2.1 with its reason payload.
- `ReproductionRecord`: per-scenario reproduction rate with n, pin, seed policy, and gap reason —
  the stochastic sibling of the deterministic replay record.
- `RiskClassBaseline` / `RiskClassComparison`: the typed inputs and output of the WP4.4 regression
  gate's decision function, so the gate is testable as data-in/data-out.

### 3.4 Regression registry

`scenarios/regression-registry.json` (or `.yaml`): each entry maps an accepted finding ID to the
scenario and test that pin it, with status (`covered`, `uncovered`, `retired-with-reason`). A
schema test asserts referenced tests exist by node ID; the WP4.4 critical-regression gate and the
≥80% coverage checkpoint are both computed from this file, so it cannot drift into decoration.

---

## 4. Work packages

### WP4.0 — Clear Phase 3 debt: make the numbers real

This is the phase's center of gravity and lands first. Until it lands, every model-facing Phase 3
figure is a claim about a simulator, and none of it may be repeated in a portfolio claim.

| # | Task | Done when |
| --- | --- | --- |
| 4.0.1 | Run the stochastic lane against a real pinned endpoint | At least one full recorded run of the agent corpus (or the named nightly subset) with a real pin, ≥5 repetitions, verified bundles, and the four numbers reported with CIs. The result is a measured fact in `docs/`, whatever it shows. |
| 4.0.2 | Calibrate token expectations per real pin, once | A one-time calibration run per pin (the same discipline as the offline pin's 2026-09-09 calibration), held fixed thereafter; token estimate vs actual reported against ±10%. |
| 4.0.3 | Report a real API cost | Actual microUSD from provider accounting vs the pre-run estimate, ±10% checkpoint met or missed *non-vacuously* for the first time. |
| 4.0.4 | Measure judge agreement with a real judge model | A real pinned judge against the frozen 24-case corpus (digest unchanged — asserted); α and κ with n and CI. Self-family bias measured by running target and judge from the same family and stating the delta (closes Phase 3 open question 2). |
| 4.0.5 | Measure stochastic variance and reproduction rate | `ReproductionRecord` per scenario; the rate reported as the lane's own number with gap reasons, never folded into deterministic replay. |
| 4.0.6 | Re-run the compromised-model property against a real model | Same property, real intent distribution: zero out-of-scope executions, invented operations recorded as refusals. The kernel claim graduates from "holds against everything a simulator emitted" to "held against everything this real model emitted on these runs". |
| 4.0.7 | `agent-demo --fixture compose` | A compose stack for the agent lane so agent routes run inside the fixture container image under the same containment as every other route; the container-lane acceptance run includes it. |
| 4.0.8 | Keep the small caveats standing | Detection delay stays labelled logical ticks; `ModelClient`'s dispatch exemption stays recorded in ADR 0008; the no-code-execution and lexical-retrieval limits stay stated wherever results are reported. |

### WP4.1 — Fast PR lane

Files: `.github/workflows/phase4.yml` (job `pr-fast`), `scenarios/smoke/` (a named list, not
copies), `make pr-check`.

| # | Task | Notes |
| --- | --- | --- |
| 4.1.1 | Select 10–20 smoke scenarios | Chosen for surface coverage (at least one per lane and per major risk class), recorded as a named list with a test asserting each member exists and is labelled. |
| 4.1.2 | Deterministic only, no model credentials | Offline provider; the job asserts no credential env vars are present so a leak into the PR lane is loud. |
| 4.1.3 | Stated wall-time target | Target proposed at ≤10 minutes (open question 3); measured on every run and asserted in the acceptance record from CI history, not one lucky run. |
| 4.1.4 | Evidence artifacts uploaded on success **and** failure | `if: always()` upload, as the existing lanes already do; the WP4.4 gates run in this lane. |

### WP4.2 — Nightly and manual real-model lane

Files: `phase4.yml` (job `nightly-stochastic`), superseding `phase3.yml`'s stochastic job as the
maintained nightly (the `phase3.yml` file itself is not edited, per the standing rule; its job is
simply no longer the one the docs point at).

| # | Task | Notes |
| --- | --- | --- |
| 4.2.1 | Real model calls with repository secrets | Endpoint, pin, and key from secrets/vars; missing credential is a recorded skip, never a fallback (existing rule, re-asserted here). |
| 4.2.2 | ≥5 stochastic repetitions with CIs | The WP3.6 machinery's first real consumer. Reduced n reported beside affected figures. |
| 4.2.3 | Adaptive-attacker and browser workflows included | The bounded attacker (WP3.4 caps) and at least the shared API/browser workflow scenarios run in this lane, so the expensive paths are exercised where the money is authorized. |
| 4.2.4 | Every failure surfaced | The §2.1 outcome vocabulary; a nightly failure files/updates a tracking issue automatically rather than scrolling away in the Actions tab. |
| 4.2.5 | Cost containment | §2.6: signed per-run cost cap, pre-flight estimate check, workflow timeout, named nightly scope from the signed manifest. |

### WP4.3 — Release lane

Files: `reporting/attestation.py`, `reporting/audit_export.py`, `scenarios/regression-registry.json`,
`scenarios/holdout/` (private/local mechanism per PRD §5), `docs/incident-runbook.md`,
`docs/retention-policy.md`, `phase4.yml` (job `release`, tag/dispatch-triggered).

| # | Task | Notes |
| --- | --- | --- |
| 4.3.1 | `RunAttestation` signing and verification | §2.4 / §3.1. ADR for the format and its stated trust model. |
| 4.3.2 | Regression registry | §3.4. Every accepted finding maps to a pinning test; coverage computed from the file; the schema test fails on a dangling test reference. |
| 4.3.3 | Held-out mutation set | Scenario mutations (payload variants, near-miss authorization cases) generated, digest-pinned, and excluded from every tuning and calibration path — enforced by a digest test, the same mechanism that protects the judge labels. Run only in the release lane. |
| 4.3.4 | Retention policy and audit export | Retention classes from Manifest 1.4 §3.2; `purpleloop audit-export` produces a self-contained, redacted, verifiable export (runs, decisions, findings, attestations) that the reviewer walkthrough consumes. |
| 4.3.5 | Incident runbook | What an evidence-integrity incident, a containment failure, a budget breach, and a suspected out-of-scope action each look like in the artifacts, and the operator response for each — written against the real event vocabulary, not hypothetically. |

### WP4.4 — Enforcing gates

Files: `reporting/gates.py` (pure decision functions), gate steps in the `pr-fast` job,
`tests/phase4/test_gates.py`, the five `gate-proof/*` branches.

| # | Gate class | Blocks when | Fed by |
| --- | --- | --- | --- |
| 4.4.1 | Scope bypass | Any policy denial bypassed, any out-of-scope execution, any authorization test failure | Deterministic property/integration suites and policy events |
| 4.4.2 | Critical regression | A registry-covered finding's pinning test fails, or a release-blocking invariant test fails | Regression registry (§3.4) + the invariant suites |
| 4.4.3 | Schema drift | Canonical bytes or digests of any versioned document change without a version bump | Existing round-trip/byte-identity tests, promoted to a named gate |
| 4.4.4 | Budget failure | A budget breach not recorded as a budget outcome, or ledger arithmetic failure | Budget/fault-injection suites |
| 4.4.5 | Per-risk-class regression | §2.3 decision function against the committed baseline | Deterministic corpus metrics only |

Each gate: a unit-tested decision function, wired into CI calling that same function, plus one
red branch proving it blocks (§2.2). Gate-isolation tests assert advisory values cannot reach any
of the five (§2.1).

### WP4.5 — Portfolio release

| # | Task | Notes |
| --- | --- | --- |
| 4.5.1 | README rewrite | One-command demo up front, architecture diagram, safety warning, sample report, honest results summary with uncertainty — the resume-ready surface (PRD §5, §11). |
| 4.5.2 | Architecture diagrams | The PRD §4 flow plus the two-plane (ADR 0008) and three-verdict (ADR 0009) diagrams, in `docs/architecture.md`. |
| 4.5.3 | Recorded demo | A recorded run of the one-command demo (asciinema or short video), linked from the README, showing the PRD §11 reviewer path including a fail-closed case. |
| 4.5.4 | Sample evidence bundle, verifiable offline | A committed passing bundle + attestation a reviewer verifies with `verify-bundle --attestation` and the shipped public key, no network. |
| 4.5.5 | Benchmark methodology | `docs/evaluation-methodology.md` completed: metrics, repetitions, intervals, judge protocol, gate definitions (§2.3), and the benchmark-limitations statement (PRD non-goal: passing ≠ safe). |
| 4.5.6 | Results narrative | The measured numbers from WP4.0 and the acceptance record, per risk class, with worst cases, n, CIs, exclusions, provenance, and limitations — never a composite score alone. |
| 4.5.7 | Reviewer walkthrough executed | §2.5: protocol, three sample artifact sets, and a timed session with an independent reviewer — or the checkpoint recorded as untested. |
| 4.5.8 | Resume claim validated word by word | The PRD §11 claim checked against measured evidence; any word the evidence does not support is changed in the claim, not argued for. |

---

## 5. Test plan

- **Unit** — attestation canonicalization, signing, and verification (including tamper cases:
  modified bundle, modified statement, wrong key); each gate decision function on constructed
  inputs both sides of its threshold (§2.3 cases included); regression-registry schema and
  dangling-reference detection; retention-class resolution; stochastic outcome classification;
  reproduction-rate arithmetic; Manifest 1.4 and Attestation 1.0 round-trips with byte-identical
  legacy bytes.
- **Gate isolation** — for each of the five gates: advisory verdicts in the input path rejected at
  the type boundary; a disagreeing judge changes no gate decision (extension of the Phase 3 test).
- **Property** — attestation verification over mutated statements (any field flip fails);
  baseline-comparison over generated corpus summaries (no false block on added scenarios or
  renamed classes; guaranteed block on lost seeded recall).
- **Contract** — audit export is self-contained (verifies with no repo checkout beyond the public
  key) and redacted (the existing secret-scanning assertions run over the export).
- **Fault injection** — nightly-lane specific: provider 429/5xx storms, mid-run credential
  revocation, cost-cap breach mid-repetition, endpoint DNS change mid-suite. Every case tears
  down, classifies its outcome (§2.1 vocabulary), and leaves a verifiable partial bundle.
- **CI-level proof** — the five red branches (§2.2), each observed red at its own gate; a green
  control branch alongside them; run URLs recorded in the acceptance record.
- **Holdout integrity** — the held-out mutation set's digest asserted unchanged across the phase's
  commits; a test asserts no calibration or tuning code path reads the holdout directory.
- **Regression** — Phase 0's 133, Phase 2's 37, Phase 3's full 339 pass unchanged; all recorded
  seed hashes and canonical digests byte-identical; the four existing workflows untouched
  (asserted by path in a test over `git diff` against the phase base, or by review checklist
  recorded in the acceptance record).

---

## 6. Acceptance checkpoint

Each number names how it is measured. Nothing is established by inspection.

| Checkpoint | Threshold | Measurement |
| --- | --- | --- |
| Real-model stochastic run exists | ≥1 full recorded run | WP4.0.1 bundles verified; four numbers with n, CI, pin. |
| Pinned replay success | ≥ 98% | Deterministic lanes' replay trials, no trial excluded; the stochastic lane reports reproduction rate separately with gap reasons — it is not inside this number. |
| Regression coverage for accepted findings | ≥ 80% | Computed from the regression registry; uncovered entries listed by name. |
| Precision on adjudicated finding sample | ≥ 95% | Human adjudication of a stated sample (size and sampling method reported with the number). |
| Reviewer reconstruction | 3 artifact sets in ≤ 30 min | Timed session with an independent reviewer (§2.5), or recorded **untested**. |
| Gates demonstrably block | 5 of 5 classes | One red branch per class, run URLs in the acceptance record; green control branch. |
| Real API cost vs estimate | ±10%, non-vacuous | Provider-billed actual vs pre-run estimate on the real pin. |
| Real-judge agreement | α/κ reported with n, CI | Real pinned judge on the frozen corpus; self-family delta stated. |
| PR-lane wall time | ≤ stated target | CI history over the phase's PRs, not one run. |
| Nightly failures surfaced | 0 silently tolerated | Every non-pass nightly outcome has a classified record and a tracking issue. |
| Prior suites | 133 + 37 + 339 passing, unchanged | Existing lanes. |
| Coverage | ≥ 85% branch | Floor, not target. |

---

## 7. Risks

| Risk | Impact | Mitigation |
| --- | --- | --- |
| A stochastic number reaches a gate | The phase's central rule is violated invisibly | §2.1: typed gate inputs, gate-isolation tests per gate, decision functions that accept only deterministic-provenance records. |
| Real-endpoint flakiness makes the nightly lane cry-wolf | Failures get tolerated, which the PRD forbids | §2.1 outcome vocabulary separates endpoint errors from scenario failures; auto-filed issues make tolerance visible; retry policy is bounded and recorded. |
| Nightly cost runs away | Real money, unattended | §2.6: signed cost cap, pre-flight estimate refusal, workflow timeout, named nightly scope. |
| The gates are wired but never proven | The checkpoint decays into an assertion | §2.2 red-branch protocol is itself a checkpoint row; the acceptance record carries the run URLs. |
| The regression gate is noisy or vacuous | PRs blocked wrongly, or never | §2.3: deterministic inputs, absolute floor on lost recall, pre-registered test and α, unit-tested both sides, explicit baseline-bump procedure. |
| Attestation theater | A signature that attests nothing | §2.4: reuse of proven signing machinery, verifier that recomputes digests, trust model stated at its real strength in the ADR. |
| Holdout leaks into tuning | The precision/holdout numbers become meaningless | Digest pinned before use; a test asserts no tuning path reads the holdout; release-lane-only execution. |
| No independent reviewer materializes | A checkpoint silently becomes self-assessment | §2.5: the honest fallback is pre-decided — recorded **untested**, protocol and samples shipped. |
| Portfolio narrative overstates | The project's credibility inverts at the last step | WP4.5.8: the resume claim is edited to fit the evidence, never the reverse; the limitations section is written from the acceptance records, which already state them. |
| Superseding `phase3.yml`'s stochastic job creates two nightlies | Double spend, split records | The old job's schedule is left but its docs pointer moves; if double-billing appears in the first week, disable the old schedule via repo settings (not by editing the file) and record the decision. |

---

## 8. Sequencing

```
WP4.0 (real-model debt: 4.0.1 pin+calibration first, then 4.0.2–4.0.6 in any order; 4.0.7 compose independent)
   ├─> §3 contracts (Attestation 1.0, Manifest 1.4, outcome/baseline records, registry schema)
   │        ├─> WP4.3 release lane (attestation, registry, holdout, retention, runbook)
   │        └─> WP4.4 gates (decision functions → CI wiring → red branches)
   ├─> WP4.1 fast PR lane ──┐   (needs only the smoke list and existing determinism)
   └─> WP4.2 nightly lane ──┴─> WP4.5 portfolio release ─> docs/phase4-acceptance.md
```

WP4.0.1 lands first because its measured cost fixes the nightly scope (WP4.2) and its calibration
fixes the token checkpoint; nothing else in the phase should be sized on guesses when one run
produces the real numbers. WP4.1 is independent and can land in parallel. WP4.4's decision
functions depend on §3's typed records; its red branches come last within the package, after the
wiring. WP4.5 needs everything, because it publishes everything — and the acceptance record is
written from commands actually run, as in every prior phase.

---

## 9. Open questions

Each needs a decision before the work package that depends on it starts. Recommendations given;
each becomes an ADR or a recorded decision in the acceptance record.

1. **Which real pin anchors the acceptance numbers?** Phase 3's open question 1, now due. A local
   Ollama/vLLM profile gives a reproducible pin and near-zero marginal cost but a weak cost story;
   a hosted API gives a real cost figure and a moving target. *Recommendation:* both, reported
   separately — local pin as the reproducibility and variance reference, one hosted pin as the
   cost and judge reference — matching the Phase 3 recommendation. Blocks WP4.0.1.
2. **Who signs, and where does the key live?** A CI-held key attests CI runs but makes local runs
   unattestable; a repo-committed private key attests nothing. *Recommendation:* per-environment
   keys — a CI key in repository secrets and a developer key outside the repo — with the key ID in
   the attestation and Manifest 1.4 naming which key IDs are acceptable per lane. Blocks WP4.3.1.
3. **What is the PR-lane wall-time target?** *Recommendation:* measure the smoke set once, set the
   target at measured p95 plus headroom, and state it — proposed ceiling 10 minutes, consistent
   with the PRD §11 ten-minute demo. Blocks WP4.1.3 only in its final number.
4. **Adjudicated precision sample: who and how many?** ≥95% precision on a sample needs a sample
   size that makes the claim non-trivial (n=20 all-correct gives a lower CI bound near 0.83).
   *Recommendation:* adjudicate every distinct accepted finding class rather than a random draw if
   the total is small — report it as a census, with the Wilson bound, not as a survey. Blocks the
   precision checkpoint.
5. **Does the nightly lane run the full 48 or a subset?** Depends entirely on the measured
   per-scenario cost from WP4.0.1. *Recommendation:* decide from that measurement, write the
   subset (if any) into `nightly_scope` in the signed manifest, and rotate coverage weekly so
   every scenario sees a real model at least monthly. Blocks WP4.2.5.
6. **Retention durations?** *Recommendation:* keep raw ledgers and attestations for the life of
   the repo (they are small and load-bearing), screenshots/traces 90 days, real-model transcripts
   30 days with digests retained indefinitely — and record the rationale in the retention policy.
   Blocks WP4.3.4.
7. **Is the independent reviewer's identity recorded?** Anonymity may make recruiting easier;
   attribution makes the measurement auditable. *Recommendation:* record role and independence
   ("had not seen the project"), not name, unless the reviewer consents. Blocks nothing; decided
   at WP4.5.7.
