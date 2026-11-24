# Loose ends across Phases 0–5 — audit and ownership

Date: November 24, 2026. Branch `worktree-agent-acd8f62c4fc3b4b3e`, from `phase-5` = `a79f185`.

The audit covered every acceptance record (`docs/phase0-acceptance.md` … `docs/phase4-acceptance.md`,
`docs/phase5/wp5.0.1-acceptance.md`), and in each one its "Known limits", debt, "Open", "not
run", "untested", caveat, and coverage-exclusion text. It also covered PRD §4, §5, §7, §8
(every phase section), and §11, the open questions in `planning/phase{2,3,4,5}-plan.md`, the
task rows of `planning/phase4-plan.md`, the as-built `docs/phase{1..4}-plan.md`, the ADRs, the
threat model, the methodology, and the operational docs. Each loose end found has one row.

**Owner vocabulary.** `closed earlier` (cites the commit or record that closed it) ·
`closed here` (fixed in this branch, with a test or a measured command) · `WP5.x.y` (the Phase 5
plan row that owns it) · `blocked: hosted credential` · `blocked: human` · `blocked: different
model family not installed` · `accepted limit` (a deliberate, documented limit, with its cite).
One more value is used, because the audit found items that fit none of these:
**`open — unowned`**. These are flagged for the orchestrator at the end of this file.

## Phase 0

| # | Loose end | Source | Owner | Note |
| --- | --- | --- | --- | --- |
| 0.1 | Kill-switch p99 covers cooperative in-process cancellation only, not an uncontrolled remote process | phase0-acceptance: Kill-switch latency | accepted limit | Stated there and in threat-model "Residual risk". The browser child's stop is row 2.4. |
| 0.2 | The ledger is tamper-evident, not immutable; the anchor is local | phase0-acceptance: Evidence; ADR 0003 | accepted limit | ADR 0003. The bundle digest is now also bound by the run attestation (ADR 0012). An external append-only store is not planned. |
| 0.3 | External policy bundles and distributed policy decisions deferred | ADR 0001 | accepted limit | ADR 0001. |
| 0.4 | Adapters are trusted; a faulty adapter could do I/O without the guard | threat-model: Residual risk | accepted limit | threat-model "Residual risk"; mitigated by the shared adapter contract suite. |

## Phase 1

| # | Loose end | Source | Owner | Note |
| --- | --- | --- | --- | --- |
| 1.1 | `fixture/relay.py` at 0% coverage in the deterministic lane | phase1-acceptance: Known limits; PRD Phase 1 debt | closed earlier | `03f05e2`: `tests/phase2/test_relay_debt.py` covers it on the host (WP2.0.1). |
| 1.2 | Image build not offline; 2 of 11 demo runs failed on registry DNS | phase1-acceptance: Known limits | closed earlier | `03f05e2`: base images pinned by digest, and a build failure reported as `partial evidence`, distinct from an evaluation failure (phase2-acceptance "Offline container demo"). The first-ever build still needs registry access: accepted limit, stated in README. |
| 1.3 | `PYTHONHASHSEED` matrix run by hand | PRD Phase 1 debt | closed earlier | `03f05e2`: `phase2.yml` matrix over 5 seeds, extended to the agent lane in `phase3.yml` (`1a83eb2`). |
| 1.4 | Detection delay is injected logical ticks | phase1/2/3-acceptance: Known limits; PRD WP4.0 | WP5.3.5 | WP5.3.5 adds an advisory wall-clock figure beside the tick figure. Until then the caveat is an accepted limit (WP4.0.8). |
| 1.5 | Budget tokens are reserved capacity, not billing | phase1-acceptance: Known limits | WP5.0.4 · blocked: hosted credential | Real token charging exists since Phase 3 (WP3.2.4). Provider-billed cost needs a hosted endpoint. |
| 1.6 | Finding reproducibility not asserted from one paired run | phase1-acceptance: Known limits | closed earlier | `f257150` (WP3.6): computed from the repetition set, with `reproducibility_basis`. |
| 1.7 | PRD §5 lists `docs/prd.md` and `policies/`, which do not exist | PRD Phase 1 debt | closed earlier | `03f05e2` (WP2.0.5). |
| 1.8 | PRD §5 still drifted from the tree: `targets/supportlab/` described as the app, `control/` approvals, Parquet, a scheduler | PRD §5 (audit) | closed here | An as-built note was added under PRD §5. `tests/phase5/test_doc_references.py::test_prd_section_5_names_only_paths_that_exist` fails if a listed path disappears. |

## Phase 2

| # | Loose end | Source | Owner | Note |
| --- | --- | --- | --- | --- |
| 2.1 | Browser bit-level determinism not claimed | phase2-acceptance: Known limits | accepted limit | ADR 0006. The browser lane reports its own replay rate. |
| 2.2 | Container/browser-only coverage exclusions (`PlaywrightDriver`, `PlaywrightSession`, `ServedSupportlab`, `ComposeSupportlab`, `supportlab-demo` body, relay/upstream `serve()`) | phase2-acceptance: Coverage exclusions | accepted limit | Named there and reconfirmed by WP3.0.3. They run in the `phase2.yml` container job. CI observation is WP5.0.7. |
| 2.3 | Wall time reported as an estimate, not held to ±10% | phase2-acceptance: Resource estimate | accepted limit | Stated in that section. The deterministic dimensions match the estimate exactly. |
| 2.4 | **Browser emergency stop: claimed as measured, but no latency was recorded** | phase2-acceptance: Browser emergency stop | open — unowned | Found here. The test writes `{"measured": true}` and drops the teardown timestamp, and it uses the in-process HTML-form driver, not a Chromium child. A correction note was added to the record (doc-only). A real figure needs a measurement in the browser lane, which no Phase 5 WP owns. |
| 2.5 | The supportlab seeded-recall / false-positive checkpoint was never written into the record | PRD Phase 2 checkpoint vs phase2-acceptance | closed here | Measured this session: recall **1.0** (18 TP, 0 FN), **0** FP over 18 negative controls, cross-surface agreement in 2 of 2 groups. This came from a one-off script, not committed, over `runtime/pinning.py` and `corpus_metrics`. Pinned going forward by `tests/phase5/test_regression_pinning.py::test_lane_aggregates_over_the_pinned_runs[supportlab]`. |
| 2.6 | PRD Phase 2 header carried no completion status, unlike Phases 0, 1, 3 | PRD §8 Phase 2 | closed here | Now "complete (`03f05e2`, 2026-09-07)", with a pointer to row 2.5. |
| 2.7 | Plan open question 1: reset strategy | planning/phase2-plan §9 | closed earlier | ADR 0005 (template database). |
| 2.8 | Plan open question 2: ownership encoding | planning/phase2-plan §9 | closed earlier | ADR 0007. |
| 2.9 | Plan open question 3: browser lane in the PR path | planning/phase2-plan §9 | closed earlier | `03f05e2`: separate container/browser job in `phase2.yml`. |
| 2.10 | Plan open question 4: Playwright browser pinning | planning/phase2-plan §9 | closed earlier | Playwright 1.58 / Chromium 145 pinned. The browser version is recorded by the driver (`adapters/browser.py`). |
| 2.11 | Plan open question 5: SSRF needs a second container | planning/phase2-plan §9 | closed earlier | Internal-only `upstream` service (phase2-acceptance "Container isolation"). |

## Phase 3

| # | Loose end | Source | Owner | Note |
| --- | --- | --- | --- | --- |
| 3.1 | No real model was called | phase3-acceptance: Known limits | WP5.0.2 | Partly closed by WP4.0.1 (`79af800`, `f20f482`): one scenario on local qwen2.5 7B. The sampled 25-scenario run is WP5.0.2. |
| 3.2 | API cost checkpoint met vacuously (measured zero) | phase3-acceptance: Token and cost | WP5.0.4 · blocked: hosted credential | — |
| 3.3 | Judge figures measure harness hardening, not a real judge | phase3-acceptance: Judge | WP5.0.5 | A real judge on the local pin is author-closable (Ollama worker). The cross-family comparison is row 5.9. |
| 3.4 | Retrieval is lexical | phase3-acceptance: Known limits | accepted limit | ADR 0011. The vector variant is the alternative in Phase 5 open question 5, not chosen. |
| 3.5 | No code-execution surface | phase3-acceptance: Known limits; PRD §7 threat coverage | WP5.5 | `codelab`, WP5.5.1–5.5.5. |
| 3.6 | `ModelClient` cannot run the adapter contract suite by dispatch | phase3-acceptance: Known limits | accepted limit | ADR 0008. |
| 3.7 | Token estimate miss: `agent-system-prompt-leakage` at −16.04% | phase3-acceptance: Token and cost | accepted limit | Reported, deliberately not re-tuned (that section). Real-pin calibration is WP5.0.3. |
| 3.8 | Agent routes never ran inside the fixture image | phase3-acceptance: Container lane | closed earlier | WP4.0.7, `672bda2`: 25 of 25 on compose, oracle hashes agree. |
| 3.9 | Attacker probes contaminated binding verdicts; published side-effect figure wrong | phase3-acceptance: correction | closed earlier | `49eb2b4` and `672bda2`. `tests/phase4/test_advisory_probe_isolation.py`; correction note in the record. |
| 3.10 | Real endpoint behaviour (latency, rate limits, partial responses, error shapes) untestable by the stub | phase3-acceptance: Coverage exclusions | WP5.0.4 · blocked: hosted credential | The local Ollama path was exercised by WP4.0.1. Hosted-endpoint 429/5xx storms are in the Phase 5 fault-injection plan (§5, WP5.2). |
| 3.11 | Imported cases are not runnable | phase3-acceptance: Corpus | WP5.6 | WP5.6.1–5.6.5. |
| 3.12 | Open question 1: reference pin, local and hosted | planning/phase3-plan §9 | WP5.0.4 · blocked: hosted credential | Local half closed by WP4.0.1. |
| 3.13 | Open question 2: judge shares the target's family | planning/phase3-plan §9 | WP5.0.5 | A same-family delta is runnable locally (qwen target, qwen judge). Cross-family is row 5.9. |
| 3.14 | Open question 3: κ or α | planning/phase3-plan §9 | closed earlier | `f06d3dc`: both reported (phase3-acceptance "Judge"). |
| 3.15 | Open question 4: nightly repetitions and per-scenario stochastic cost | planning/phase3-plan §9 | WP5.0.2 | 5 repetitions are fixed in the lanes. The per-scenario real cost measurement is WP5.0.2/5.0.3. |
| 3.16 | Open question 5: model-driven attacker | planning/phase3-plan §9; `control/attacker.py` docstring | WP5.1.6 | — |
| 3.17 | Open question 6: where utility under attack is measured | planning/phase3-plan §9 | closed earlier | `f257150`. |
| 3.18 | Open question 7: imported cases in the 30–50 count | planning/phase3-plan §9 | closed earlier | `d347ddb`: not counted. Separate reporting is WP5.6.3. |

## Phase 4

| # | Loose end | Source | Owner | Note |
| --- | --- | --- | --- | --- |
| 4.1 | Real-model reproduction only at temperature 0; no sampled variance | phase4-acceptance: Summary, WP4.0.5 | WP5.0.2 | — |
| 4.2 | Precision on an adjudicated sample: untested | phase4-acceptance: Summary | WP5.0.8 · blocked: human | The `adjudicate` CLI and record format are author-buildable. The adjudication itself needs a human. |
| 4.3 | Independent reviewer session: untested | phase4-acceptance: Summary | WP5.0.9 · blocked: human | The protocol and samples are in place. |
| 4.4 | CI-observed red branches not run (not pushed) | phase4-acceptance: Enforcing gates | WP5.0.7 | Needs the five `gate-proof/*` branches pushed, which requires the user's go-ahead to push. |
| 4.5 | Real API cost not met | phase4-acceptance: Summary | WP5.0.4 · blocked: hosted credential | — |
| 4.6 | Real-judge agreement not run | phase4-acceptance: Summary, WP4.0.4 | WP5.0.5 | — |
| 4.7 | Tests added after the 435-test run never counted together | phase4-acceptance: Quality gate, Follow-up | closed earlier | `6f3feb0` (WP5.0.1): 472 passed, 3 skipped. |
| 4.8 | A full-suite run stalled (92 min, ~9 min CPU), cause undetermined | phase4-acceptance: Quality gate | closed earlier | `6f3feb0`: reproduced as system sleep. Likely, but unconfirmed for the original run. |
| 4.9 | `pr-fast` wall time in CI never measured | phase4-acceptance: Fast PR lane; plan 4.1.3 | WP5.0.7 | — |
| 4.10 | Regression pinning is corpus-granular | phase4-acceptance: Regression registry | closed here | `ae2ddc2` (WP5.0.10): 48 per-scenario node IDs. One injected regression names exactly one finding (`docs/phase5/wp5.0.10-acceptance.md`). |
| 4.11 | Release attestation used an ephemeral key and recorded no commit | phase4-acceptance: Release lane | WP5.0.12 · blocked: human | The `release` job signs with `PURPLELOOP_ATTESTATION_KEY` from repository secrets. Only the repository owner can provision that secret. |
| 4.12 | Retention policy and incident runbook never exercised | phase4-acceptance: Release lane | open — unowned | No WP runs a drill. A tabletop exercise of one runbook section is author-closable. |
| 4.13 | WP4.0.2 real-pin token calibration not fixed | phase4-acceptance: WP4.0 table | WP5.0.3 | — |
| 4.14 | WP4.0.6 compromised-model property against a real model | phase4-acceptance: WP4.0 table | WP5.0.6 | Runnable on the local pin (Ollama worker). |
| 4.15 | Only 1 of the 13 scenarios using `retrieval-provenance-guard` ran on a real model | phase4-acceptance: WP4.0.1 re-run | WP5.0.2 | — |
| 4.16 | Email is the only sink gated by retrieval provenance | phase4-acceptance: WP4.0.1 re-run | WP5.0.2 | WP5.0.2 triages each real-model regression as an application finding, fixed in the fixture as `f20f482` was. |
| 4.17 | Provenance taint is per actor, most recent run, not full information flow | phase4-acceptance: WP4.0.1 re-run | accepted limit | Stated there as the fixture's model of provenance. |
| 4.18 | Two of the three WP4.0.1 fixes were not revert-checked | phase4-acceptance: WP4.0.1 | open — unowned | Tried here. Reverting the `b7fe527` and `c557c80`+`6322c03` source changes makes their tests fail, but only at import (`PinnedModelLabel` and `RUN_STOP_REASONS` disappear with the fix). A behavioural revert-check was not done. |
| 4.19 | Nightly CI job has never run | phase4-acceptance: Known limits | WP5.0.7 | — |
| 4.20 | New `pragma: no cover` lines (compose branches, two `OSError` handlers) | phase4-acceptance: Coverage exclusions | accepted limit | Named there. The compose branches were executed by the compose runs. |
| 4.21 | GitGuardian exclusion of `baselines/` and `docs/samples/` removes scanning | phase4-acceptance: Follow-up | closed earlier | `2bd3c2d`: `tests/phase4/test_sample_hygiene.py` replaces it. |
| 4.22 | Committed samples and corpus baseline named a commit that did not produce them | phase4-acceptance: Follow-up | closed earlier | `2bd3c2d`: regenerated at `672bda2`. |
| 4.23 | Plan 4.2.3: nightly lane should run the attacker **and browser workflows** | planning/phase4-plan WP4.2 | open — unowned | `phase4.yml` nightly runs one agent scenario with `--attacker`. No browser workflow. `phase4.yml` may not be edited, so this would be a `phase5.yml` job. |
| 4.24 | Plan 4.2.4: a nightly failure files or updates a tracking issue | planning/phase4-plan WP4.2 | open — unowned | Not implemented. A failure only fails the job. |
| 4.25 | Plan 4.2.5 / open question 5: nightly scope from the signed manifest | planning/phase4-plan WP4.2, §9 | open — unowned | `Phase4Grants.nightly_scope` exists, but the job hard-codes `agent-indirect-ticket`. Sizing the scope is WP5.0.2. Wiring it is unowned. |
| 4.26 | Plan 4.5.1: README results summary with uncertainty | planning/phase4-plan WP4.5 | closed here | README "Results so far": each row cites its record, with a "not yet measured" list. `tests/phase5/test_doc_references.py` checks every link resolves. |
| 4.27 | Plan 4.5.2: architecture diagrams (PRD §4 flow, two planes, three verdicts) | planning/phase4-plan WP4.5 | closed here | Three Mermaid diagrams in `docs/architecture.md` "Diagrams". |
| 4.28 | Plan 4.5.3: recorded demo | planning/phase4-plan WP4.5; PRD WP4.5 | closed here | `72c9d69` (WP5.0.11). |
| 4.29 | Plan 4.5.6: per-risk-class results narrative | planning/phase4-plan WP4.5 | closed here (summary only) | The README table is a summary. The per-risk-class figures live in `baselines/corpus-baseline.json` and the report's per-risk-class section (WP3.6.4). A longer narrative was not written. |
| 4.30 | Plan 4.5.8: resume claim validated word by word | planning/phase4-plan WP4.5; PRD §11 | WP5.0.12 | — |
| 4.31 | Open question 2: per-environment attestation keys | planning/phase4-plan §9 | closed earlier | `672bda2`: Manifest 1.4 `attestation_key_ids`. The CI key's provisioning is row 4.11. |
| 4.32 | Open question 3: PR-lane wall-time target | planning/phase4-plan §9 | WP5.0.7 | 600 s target stated and met locally (12.131 s in the recorded run). CI history is WP5.0.7. |
| 4.33 | Open question 4: adjudication census | planning/phase4-plan §9 | WP5.0.8 · blocked: human | — |
| 4.34 | Open question 6: retention durations | planning/phase4-plan §9 | closed earlier | `672bda2`: `docs/retention-policy.md`. |
| 4.35 | Open question 7: reviewer identity | planning/phase4-plan §9 | closed earlier | Decided in `docs/reviewer-walkthrough.md` (role and independence, name only with consent). The session is row 4.3. |
| 4.36 | PRD Phase 4 checkpoint wording out of date (test count, granularity, "a real stochastic run" listed as never run) | PRD §8 Phase 4 | closed here | Amended in place, citing WP5.0.1, WP5.0.10, WP4.0.1, and WP5.0.11. |

## WP5.0.1

| # | Loose end | Source | Owner | Note |
| --- | --- | --- | --- | --- |
| 5.1 | An uninterrupted (AC power, lid open) full-suite wall time | wp5.0.1-acceptance: Status | closed here | See "Full suite at the end of this branch" below. |

## PRD requirements and technology choices never built

| # | Loose end | Source | Owner | Note |
| --- | --- | --- | --- | --- |
| 5.2 | Dry-run execution | PRD §7 Safety kernel | WP5.1.2 | Shadow mode. |
| 5.3 | **Detect repeated or no-progress action-state hashes and stop runaway loops** | PRD §7 Safety kernel | open — unowned | No detector exists. Today loops are prevented by structure: plans are acyclic DAGs with signed node and depth limits, the attacker has attempt and depth caps, and budgets and wall time are hard. The requirement becomes live with the WP5.1.6 model-driven attacker and Phase 6 agents. No WP names it. |
| 5.4 | Rollback checks | PRD §7 Safety kernel | closed earlier | Reset verified by snapshot-hash equality before each leg (ADR 0005, `03f05e2`). |
| 5.5 | OpenTelemetry event export | PRD §4 | WP5.3.1 | — |
| 5.6 | DuckDB/Parquet analysis output | PRD §4, §5 | WP5.3.6 | — |
| 5.7 | Bounded LangGraph attack policies (optional) | PRD §4 | WP5.1.6 | The plan's model-driven attacker profile. LangGraph itself is not chosen anywhere. |
| 5.8 | Evaluator resistance to contamination, non-determinism, reward hacking, aggregation masking | PRD §7 Judging | WP5.6.3 (contamination) | Non-determinism: repeated trials and order swaps (`f06d3dc`). Reward hacking: the rubric-gaming cases. Aggregation masking: no composite score is ever reported. Those three were closed earlier. Contamination: `public_exposure` labelling, WP5.6.3. |
| 5.9 | A second real model from a different family (matrix rows, cross-family judge delta) | Phase 5 plan WP5.2.2, WP5.0.5 | blocked: different model family not installed | All installed local models are Qwen-lineage. A hosted pin would also do: blocked: hosted credential. |
| 5.10 | Human calibration of the judge | PRD §7 Judging | WP5.0.8 · blocked: human | And WP5.4 (review UI). |
| 5.11 | Risk-approval documents and an approver key | PRD §8 Phase 5; Phase 5 plan open question 3 | WP5.1.4 · blocked: human | A second-person approver is a human; otherwise an offline author key, recorded as such. |
| 5.12 | Pinned models × defenses matrix | PRD §8 Phase 5 | WP5.2 | — |
| 5.13 | Self-hosted observability profile; human-review UI | PRD §8 Phase 5 | WP5.3, WP5.4 | — |
| 5.14 | Additional disposable target fixture | PRD §8 Phase 5 | WP5.5 | — |
| 5.15 | Benchmark subsets runnable | PRD §8 Phase 5 | WP5.6 | — |
| 5.16 | v1 not declared: no tag, no clean-commit attestation | Phase 5 plan §0 | WP5.0.12 | — |
| 5.17 | PRD §11 item 6, "CI artifacts" a reviewer can inspect | PRD §11 | WP5.0.7 | — |

## Documents that no longer matched the facts

| # | Loose end | Source | Owner | Note |
| --- | --- | --- | --- | --- |
| 6.1 | README safety warning: "There is no … live-model adapter … all model responses come from offline fixtures" | README | closed here | Reworded. Offline is the default and the PR-lane rule. A live model is reached only through the opt-in lane at a signed origin (ADR 0008). |
| 6.2 | README documentation list omitted the Phase 5/6 plans and the Phase 5 notes | README: Documentation | closed here | Link check in `tests/phase5/test_doc_references.py`. |
| 6.3 | `docs/prd.md` listed only the Phase 0–2 acceptance records and the Phase 2 plan | docs/prd.md | closed here | `test_the_index_lists_every_acceptance_record` fails if a record is added without an entry. |
| 6.4 | Methodology said no real endpoint had been used | docs/evaluation-methodology.md: Phase 4 note | closed here | Now names the one WP4.0.1 run. |
| 6.5 | Threat model stopped at Phase 2 (no model plane, judge, attacker, gates, attestation) | docs/threat-model.md | closed here | "Phase 3 and Phase 4 additions" section, each row citing its ADR or test. |
| 6.6 | **Committed sample Inspect logs embed the author's absolute home path** | docs/samples/{passing-run,incident}/inspect/*.json | blocked: human | Found here. The samples are digest-inventoried and attested, so scrubbing them means regenerating and re-attesting both sets. `test_sample_hygiene.py` does not scan for home paths. Author decision. |

## Full suite at the end of this branch

Command, at `cc6df0a` (clean tree), on AC power (`pmset -g batt`: "Now drawing from 'AC
Power'"), 21:40:54Z–21:58:54Z:
`caffeinate -i -s /usr/bin/time -l uv run pytest --junitxml=artifacts/junit-loose-ends.xml --durations=15`

| Item | Result |
| --- | --- |
| Collected | **554** (JUnit `tests=554 failures=0 errors=0 skipped=3`) |
| Passed / skipped / failed | **551 / 3 / 0**. The 3 skips are the same container- and PostgreSQL-gated tests as in WP5.0.1. |
| Branch coverage | **89.49%** (floor 85%) |
| Suite time | **1,078.20 s** by pytest's clock, **1,079.98 s** real by `/usr/bin/time`, CPU 970.43 s user + 55.80 s sys |

Real time and pytest time agree within 2 s, so this run was **uninterrupted**, which closes row
5.1. Against WP5.0.1 (475 collected, 1,039 s awake), the 79 new `tests/phase5` tests are the
whole difference in count. The time difference is +39 s, consistent with the ~41 s that the
per-scenario pins measured on their own (WP5.0.10). The gates over this JUnit
(`purpleloop gates <smoke bundle> --junit artifacts/junit-loose-ends.xml --risk-current
baselines/corpus-baseline.json`) exited 0. `critical-regression` read `REGISTRY_TESTS_PASSED — 48
covered finding(s)` with both the per-scenario and the corpus tests present.

## Flagged for the orchestrator: `open — unowned`

These have no owner in the Phase 5 plan and fit no blocked category. Each is small, but none was
small enough, or local enough, to fix inside this audit:

1. **2.4** Browser-lane emergency-stop latency was never measured. The Phase 2 claim is now
   corrected in its record.
2. **4.12** Retention policy and incident runbook have never been exercised.
3. **4.18** Two WP4.0.1 fixes are revert-checked at import level only.
4. **4.23** The nightly lane has no browser workflow.
5. **4.24** A nightly failure files no tracking issue.
6. **4.25** The nightly scope is hard-coded, not read from the signed `nightly_scope`.
7. **5.3** There is no no-progress or runaway-loop detector (PRD §7). It is structurally moot
   today and becomes live with WP5.1.6 and Phase 6.
