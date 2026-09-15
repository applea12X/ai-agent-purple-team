# Phase 4 Acceptance Record

Date: September 15, 2026

Measured on a local macOS development environment (Darwin 25.6.0, Python 3.12, Docker Engine
29.7.2). Every number below was observed from a command that was actually run. **No real model was
called in producing any number in this document.** No branch was pushed, so nothing here was
observed in GitHub Actions. Where a checkpoint needs either of those, it is recorded as not run
rather than as met.

## Summary against the Phase 4 checkpoint

| Checkpoint | Threshold | Result |
| --- | --- | --- |
| Pinned replay success | ≥ 98% | **Met for the deterministic lanes: 229 of 229 (1.0).** The real-model reproduction rate is **not run**. |
| Regression coverage for accepted findings | ≥ 80% | **48 of 48 (1.0)**, at corpus-test granularity (see caveat) |
| Precision on an adjudicated finding sample | ≥ 95%, with n and method | **Untested.** No human adjudication was performed. |
| Independent reviewer reconstructs three runs in ≤ 30 min | Measured with a real reviewer | **Untested.** Protocol and sample sets are in place. |
| CI blocks each of the five gate classes | One red branch per class | **Proven locally through the CI command, 5 of 5. CI-observed red branches not run** (not pushed). |
| Real API cost within ±10% of estimate | Non-vacuous | **Not run.** Needs a real endpoint. |
| Real-judge agreement with n and CI | Reported | **Not run.** Needs a real judge model. |
| Prior suites | Pass unchanged | **Met.** No Phase 0–3 test file was edited. |
| Coverage | ≥ 85% branch | **88.73%** |

## Quality gate

Commands: `uv run ruff check .`, `uv run ruff format --check .`, `uv run mypy`,
`uv run pytest --junitxml=artifacts/junit.xml`.

- Ruff lint and format checks passed; mypy strict passed for 80 source files.
- **435 tests passed, 3 skipped. Branch-aware coverage 88.73%** against the 85% floor. Wall time
  753 s.
- The three skips are the same container- and PostgreSQL-gated tests as in Phase 3.
- One test, `tests/phase4/test_corpus_baseline.py`, was added **after** that run. It passed when run
  on its own (1 passed, 19.68 s) and is not included in the 435.

New modules measured in that run: `reporting/gates.py` 97%, `scoring/phase4.py` 99%,
`schemas/phase4.py` 92%, `reporting/attestation.py` 92%, `control/holdout.py` 92%,
`reporting/audit_export.py` 88%, `phase4_cli.py` 79%.

**A run that stalled.** The first full-suite run of this phase was still unfinished after about 92
minutes, having used only about 9 minutes of CPU. It was killed. Three later complete runs took 952
s, 678 s, and 753 s. The cause was not determined; it is recorded here rather than dropped.

## Prior suites unchanged

- No file under `tests/unit`, `tests/contract`, `tests/property`, `tests/integration`,
  `tests/acceptance`, `tests/fault_injection`, `tests/phase1`, `tests/phase2`, or `tests/phase3`
  was modified. All of them ran inside the 435.
- The `phase0`–`phase3` workflow files were not edited.
- Manifest 1.2 and 1.3 documents keep byte-identical canonical bytes and digests with the 1.4
  fields present. This is asserted by `test_existing_manifests_keep_byte_identical_canonical_bytes`.
- One Phase 3 test failed against this phase's first implementation, and the **code** was fixed,
  not the test. See "Defects found and fixed".

## Replay

Measured in the final suite run.

| Lane | Trials | Matched | Rate | What the test asserts |
| --- | --- | --- | --- | --- |
| Phase 1 | 100 (20 × 5) | 100 | 1.0 | ≥ 95 (the count is read from `artifacts/phase1-acceptance.json`) |
| supportlab, API | 39 (3 × 13) | 39 | 1.0 | exactly 1.0 per scenario |
| supportlab, browser (HTML-form driver) | 15 (3 × 5) | 15 | 1.0 | exactly 1.0 per scenario, reported separately |
| agent (offline provider) | 75 (3 × 25) | 75 | 1.0 | no mismatched scenario |

The deterministic total is 229 of 229, which meets the ≥ 98% checkpoint. The Phase 1 test itself
only asserts ≥ 95. The 100 here is the measured count, not what the assertion guarantees.

The **stochastic lane's** replay number — its reproduction rate against a real pinned endpoint —
does not exist yet. The machinery (`ReproductionRecord`, written as `reproduction.json`) is tested,
and on the offline provider it reads 1.0. That reading describes the scripted stand-in, not a model.

## Enforcing gates

Command:
`purpleloop gates <smoke bundle> --junit artifacts/junit.xml --risk-current artifacts/corpus-current.json`
(`artifacts/gates.json`).

Clean run over the final smoke bundle. All five gates passed:

| Gate | Decision | What it examined |
| --- | --- | --- |
| scope-bypass | pass | 302 executed results, each preceded by a policy permit |
| critical-regression | pass | 48 covered findings, every pinning test present and passed in the JUnit report |
| schema-drift | pass | 6 reference digests unchanged against `baselines/schema-digests.json` |
| budget-failure | pass | 14 runs within signed limits, with no execution after a budget denial |
| risk-class-regression | pass | 13 risk classes compared at the pre-registered alpha = 0.05 |

**Injected violations**, one per class, run through the same command and the same bundle
(`artifacts/gates-inject-<class>.json`). Each exited 1 with **exactly one** gate blocked:

| Injected class | Blocking reason |
| --- | --- |
| scope-bypass | `SCOPE_BYPASS`: an execution with no policy permit |
| critical-regression | `REGISTRY_TEST_FAILED` |
| schema-drift | `SCHEMA_DIGEST_DRIFT` |
| budget-failure | `BUDGET_VIOLATION`: 601 requests against a signed limit of 600 |
| risk-class-regression | `RISK_CLASS_REGRESSION`, via `NEWLY_MISSED_SEEDED_FINDING` at p = 1.0 |

The last row is the absolute floor working as pre-registered. With a class this small, one lost
seeded finding is nowhere near statistically significant, and the gate still blocks, because a
lost detection with deterministic verdicts is a fact rather than a sample.

The same five cases run as `test_each_injected_violation_blocks_its_own_gate`. The gate logic is
unit-tested on both sides of every threshold, and advisory verdicts are rejected at the gate
boundary (`tests/phase4/test_gates.py`).

**What this does not prove.** PRD requires "a deliberately failing branch per class" observed in
CI. No branch was pushed, so wiring *inside GitHub Actions* is untested. That covers the
`pr-fast` job's step order and its reading of the uploaded JUnit file. The local runs prove that
the command CI calls blocks correctly on a real bundle; they do not prove the workflow calls it
correctly.

## Regression registry

`scenarios/regression-registry.json` maps all 48 corpus scenarios to a pinning test. Coverage is
**48 of 48 (1.0)**. `test_no_dangling_test_references` confirms every named test file and function
exists.

**Granularity caveat.** The 48 findings are pinned by three corpus-level tests, one per lane. A
failure in one of those blocks the gate, and the gate's detail lists every finding that test pins,
but the registry alone cannot say which finding regressed. That meets the checkpoint as written.
It is coarser than one test per finding, and this record says so rather than letting 1.0 imply
otherwise.

## Fast PR lane

Command: `purpleloop smoke-demo`, run on an otherwise idle machine.

- **14 of 14 passed** across all three lanes: 2 Phase 1, 6 supportlab (1 of them browser), and 6
  agent. The suite bundle verified.
- Wall time **11.72 s** against the stated 600 s smoke target.
- **The PR lane is not 12 seconds.** The `pr-fast` job also runs the full 435-test suite (753 s
  locally) and the corpus metrics, so its local equivalent is about 13 minutes. Its wall time in CI
  was not measured.

## Release lane

- **Holdout.** `purpleloop holdout-check` denied **17 of 17** near-miss mutations with the unmutated
  base action permitted as a positive control. The digest `84eec578…` is pinned in
  `tests/phase4/test_holdout.py`. A grep test confirms no module outside the holdout executor and
  its CLI reads the holdout directory.
- **Attestation.** The 125-bundle agent suite was attested, and `verify-bundle --attestation`
  returned valid. The key was **ephemeral** and the attestation records it as such. **No code
  commit was recorded**: the working tree held uncommitted changes, and naming `HEAD` would have
  misstated the materials. The lockfile digest, corpus digest, scenario digests, and model pin ids
  were recorded. Tamper cases (modified statement, modified inventory, wrong key, incomplete
  bundle) each fail in `tests/phase4/test_attestation.py`.
- **Audit export.** `purpleloop audit-export` over the same suite produced 125 runs and 7,500
  admission, policy, budget, defense, and termination decisions, with the attestation embedded.
- **Retention policy and incident runbook** are written (`docs/retention-policy.md`,
  `docs/incident-runbook.md`). Neither has been exercised by a real incident.

## WP4.0.7 — the agent surface under container containment

Command: `purpleloop agent-demo --fixture compose`, on the fixed runner.

- **25 of 25 passed** with the fixture running in the container image on PostgreSQL. The suite
  bundle verified, wall time was 216 s, and teardown left **zero** containers.
- Compared with the in-process run of the same code: **25 of 25 statuses and 25 of 25 oracle
  hashes agree**.
- The first compose probe seeded state hash `e7cfb55e…`, the same hash Phase 3 recorded for the
  agent surface on both PostgreSQL and SQLite.

This closes the gap Phase 3 named: the agent routes now run inside the fixture image under the same
containment as every other route.

## The four numbers, re-measured

Command: `purpleloop agent-demo --repetitions 5`, the same configuration as Phase 3's figures
(attacker and judge on, offline provider).

| Measure | min | max | mean across 25 scenarios |
| --- | --- | --- | --- |
| Clean utility | 1.0 | 1.0 | 1.0 |
| Utility under attack | 1.0 | 1.0 | 1.0 |
| Attack success | 1.0 | 1.0 | 1.0 |
| Executed unauthorized side effects | **0.0** | **1.0** | **0.96** |

- 125 bundles verified, with zero exclusions and 25 of 25 reproducible.
- A representative figure reads
  `{value: 1.0, n: 5, ci: [0.566, 1.0], provenance: pinned-stochastic, model_pin_id: offline-scripted}`.
- Phase 3 published side effects as min 2.0, max 3.0, mean 2.96. That figure was wrong, for the
  reason below. The other three numbers are unchanged.

## Defects found and fixed during acceptance

Each was found by a command that failed or disagreed with a recorded claim. Each fix is covered by
a test.

- **Attacker probes decided binding verdicts (pre-existing since Phase 3).** This was the most
  consequential finding. Running the agent corpus on the new compose fixture reported
  `agent-indirect-markdown` as a regression. It looked like a container difference and was not: it
  reproduced identically in process, and at the Phase 3 commit in a clean worktree.
  - **Root cause.** The runner executed the bounded attacker's proposals inside the attack stage,
    *before* the scored snapshot. The attacker's writes reached the state the security oracle
    reads, its responses reached the oracle's input, and its telemetry reached the unauthorized
    side-effect count. On the markdown scenario, its CRM writes to `admin-a` made an effective
    `retrieval-provenance-guard` defense look like it failed.
  - **Measured before the fix** (attacker on, n = 1 per scenario): baseline side effects min 2, max
    3, mean 2.96, matching Phase 3's published figure exactly. **22 of 25 defended replays**
    recorded unauthorized side effects, and `agent-demo` passed 24 of 25.
  - **Why the type system missed it.** ADR 0009 guarded the *value* of a verdict against advisory
    input, and not the *inputs* a binding oracle reads.
  - **Fix.** Probes now run after every binding measurement of the leg (security, utility under
    attack, detection), marked by an `ADVISORY_PROBES_AFTER_BINDING` lifecycle event. They still
    execute through `SafetyRuntime` and are charged to the leg budget.
  - **Tests.** `tests/phase4/test_attacker_isolation.py` has three tests, and **all three fail
    against the Phase 3 runner**.
  - **Records updated.** A correction note is prepended to `docs/phase3-acceptance.md`, and ADR
    0009 carries an amendment.
- **A skipped stochastic lane wrote into its output directory.** This phase's first version
  recorded the classified skip as `outcome.json`, which created the directory. That broke Phase 3's
  invariant that "a skipped lane must not write a bundle", and
  `test_the_stochastic_lane_exits_zero_when_it_is_skipped` failed. The code was fixed and the test
  left untouched: outcomes now always print, and are written to disk only when the run already
  created its directory.
- **The audit export assumed a per-bundle authorization key at the suite root.** Suite bundles keep
  keys per run, so exporting any suite failed. The key is now embedded per run.
- **A holdout mutation set an enum field to a bare string.** It still denied correctly, but it
  emitted a serializer warning on every run and relied on implicit coercion. The mutation now
  constructs the enum.
- **Two metrics had no test that fails when faked.** `risk_class_metrics` (the risk-class gate's
  input) and the `corpus-baseline` command had only been exercised by running them by hand. Both now
  have tests: `test_risk_class_metrics.py` (missed findings, false positives, unlabelled scenarios,
  advisory input) and `test_corpus_baseline.py` (the committed baseline must equal what the code
  produces).

**One design error caught before it shipped.** The attacker-boundary marker was first written as a
`PROPOSAL` event. That event kind requires an operation and a decision, so the marker would have
needed null placeholders, which is the way an evidence-completeness metric turns decorative. It was
changed to a `LIFECYCLE` event before any test ran.

## Coverage exclusions

New `pragma: no cover` lines in this phase:

- `agent_cli.py`: the two `--fixture compose` branches. These are container lane only, and **were
  executed** by the compose runs above, just not under the coverage tool.
- `agent_cli.py`: the `OSError` handler around writing `outcome.json`, which must never mask the
  failure it records.
- `phase4_cli.py`: the `OSError` handler for a missing `git` binary.

The Phase 2 and Phase 3 exclusions are unchanged.

## WP4.0 — status of the Phase 3 debt

| Item | Status |
| --- | --- |
| 4.0.1 Run the stochastic lane against a real model | **Not run.** No endpoint was configured. The lane, its outcome classification, and its CI job exist. |
| 4.0.2 Calibrate token expectations per real pin | **Not run.** Depends on 4.0.1. |
| 4.0.3 Report a real API cost | **Not run.** Depends on 4.0.1. |
| 4.0.4 Judge agreement with a real judge, self-family delta | **Not run.** |
| 4.0.5 Stochastic variance and reproduction rate | **Machinery done and tested; real number not run.** |
| 4.0.6 Compromised-model property with a real model | **Not run.** |
| 4.0.7 Agent routes under container containment | **Done:** 25 of 25, full agreement with in process. |
| 4.0.8 Keep caveats standing | Detection delay is still logical ticks; retrieval is still lexical; there is still no code-execution surface. All three are unchanged and stated. |

## Known limits

- **No real model was called.** Every model-facing figure in this phase and in Phase 3 describes the
  scripted stand-in. The Phase 4 nightly lane exists so that changes, and it has not run.
- **Nothing was observed in CI.** The workflows are written and the commands they call were run
  locally. Job ordering, secret handling, artifact upload, and the red branches in Actions are
  untested.
- **The two human checkpoints are untested.** No adjudicated precision sample and no independent
  reviewer session. `docs/reviewer-walkthrough.md` and `docs/samples/` are ready for the session.
  The incident sample is labelled as deliberately corrupted.
- **Regression pinning is corpus-granular** (see the caveat above).
- **The attestation used an ephemeral key and recorded no commit.** It proves this bundle was bound
  to these materials, not who ran it or which commit produced it.
- **A passing run is evidence about these exact fixtures, seeds, defenses, and the offline
  provider only.** It does not prove a target or a model is secure.
