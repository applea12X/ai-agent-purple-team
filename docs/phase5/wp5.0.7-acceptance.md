# WP5.0.7 — CI-observed gates and lanes

Date: November 24, 2026

Observed in GitHub Actions (`github.com/applea12X/ai-agent-purple-team`, workflow
`.github/workflows/phase4.yml`, hosted `ubuntu-latest` runners). Every branch below was cut from
`origin/main` = `a79f185`. Each was pushed and dispatched with
`gh workflow run phase4.yml --ref <branch>` at 21:13Z. All six runs were concurrent. Every
number below comes from `gh run view <id> --json jobs` (step and job timestamps, second
resolution) or `gh run view --job <id> --log`. No model was called. No repository setting or
secret was read or changed.

## Result

Phase 4 checkpoint: "CI demonstrably blocks each of the five classes in WP4.4, proven by a
deliberately failing branch per class". **Met, observed in CI.** Each red branch failed at step
12, `Enforcing gates (ADR 0013)`, of job `pr-fast`. Steps 1–11 passed in every run, and exactly
one gate blocked. The control passed every step. Every run was right on the first attempt, so
none was re-run.

| Class | Branch | Commit | Run | Failing step | Reason code (gate output) | Earlier steps green |
| --- | --- | --- | --- | --- | --- | --- |
| control | `gate-proof/control` | `37e4e9d` | [45488892962](https://github.com/applea12X/ai-agent-purple-team/actions/runs/45488892962) | none, run **success** | all five pass: `NO_BYPASS_OBSERVED`, `REGISTRY_TESTS_PASSED`, `CANONICAL_BYTES_STABLE`, `BUDGETS_HELD`, `WITHIN_BASELINE` | yes, all 13 steps |
| scope-bypass | `gate-proof/scope-bypass` | `5782c5a` | [45488898339](https://github.com/applea12X/ai-agent-purple-team/actions/runs/45488898339) | 12 Enforcing gates | `SCOPE_BYPASS`: "seq 78: executed without a policy permit" | yes, 1–11 |
| critical-regression | `gate-proof/critical-regression` | `2b69264` | [45488904584](https://github.com/applea12X/ai-agent-purple-team/actions/runs/45488904584) | 12 Enforcing gates | `REGISTRY_TEST_NOT_RUN`: "pinning tests absent from the report for: bola, direct-injection, indirect-injection, mass-assignment, refund" | yes, 1–11 |
| schema-drift | `gate-proof/schema-drift` | `e4d2381` | [45488909709](https://github.com/applea12X/ai-agent-purple-team/actions/runs/45488909709) | 12 Enforcing gates | `SCHEMA_DIGEST_DRIFT`: "drifted: authorization-manifest-1.3" | yes, 1–11 |
| budget-failure | `gate-proof/budget-failure` | `30bf3cd` | [45488914237](https://github.com/applea12X/ai-agent-purple-team/actions/runs/45488914237) | 12 Enforcing gates | `BUDGET_VIOLATION`: "gate-proof: requests charged 601 over signed limit 600" | yes, 1–11 |
| risk-class-regression | `gate-proof/risk-class-regression` | `6ec9980` | [45488918480](https://github.com/applea12X/ai-agent-purple-team/actions/runs/45488918480) | 12 Enforcing gates | `RISK_CLASS_REGRESSION`: "approval-spoofing: NEWLY_MISSED_SEEDED_FINDING (p=1.0)" | yes, 1–11 |

In every red run, the other four gates printed `pass` with the same reason codes as the
control. The step exited 1 (`##[error]Process completed with exit code 1.`). Step 13 (upload)
still ran because of `if: always()`, and each run carries a `phase4-pr-evidence` artifact of
612–613 kB (`gh api .../actions/runs/<id>/artifacts`, metadata only, not downloaded).

The pytest step (step 9) in each run:

| Branch | pytest result | Coverage |
| --- | --- | --- |
| control, scope-bypass, schema-drift, budget-failure, risk-class-regression | 472 passed, 3 skipped | 89.40% |
| critical-regression | 471 passed, 3 skipped, **1 deselected** (`collected 475 items / 1 deselected / 474 selected`) | 89.39% |

## How each violation was made, and why

Every red branch is a single commit, and its message says "DELIBERATE GATE PROOF, NEVER MERGE".
The branches stay on origin as the evidence. Each approach was chosen so that steps 1–11 stay
green. A violation that an earlier step catches would prove the earlier step, not the gate.

**critical-regression is a genuine violation, not an injection.** The commit adds
`--deselect tests/phase1/test_loop.py::test_all_five_paired_loops` to pytest's `addopts` in
`pyproject.toml`. That test is the registry's pinning test for five covered findings. The suite
stays green because the test simply does not run. This is the failure mode the gate exists for: a
pinning test that is silently dropped, skipped, or deselected. Only the gate catches it, because
no test checks that the JUnit report is complete. No test file and no workflow was edited.

**The other four use `--inject <class>`.** Each commit adds one line, `--inject <class> \`, to the
gates command in `phase4.yml`. This is an edit to `phase4.yml`, which the standing rules forbid
on any branch that merges. It is allowed here only because these branches exist to be red and
never merge. The gates step prints `INJECTED <class>: a deliberately violating input (red-branch
proof)` before its decisions, and the CI log shows that line in each of the four runs.

Why a genuine violation was not used for these four:

- **scope-bypass, budget-failure.** The gates read the smoke bundle that CI builds fresh from the
  kernel at step 10. A real bypass or over-budget run needs a kernel change, and the suite at step
  9 would catch it first. Appending or editing an event in a bundle ledger breaks its hash chain.
  The command then fails on ledger verification (`FAILED: ...`), not with the gate's reason code.
- **schema-drift.** A genuine drift is caught one step earlier. A genuine drift means one changed
  digest in `baselines/schema-digests.json`, or a changed reference document. The standing check
  `tests/phase4/test_gates.py::test_committed_schema_baseline_matches_the_current_code` catches
  it. Checked locally: one digest changed in `baselines/schema-digests.json`, then
  `uv run pytest -q --no-cov tests/phase4/test_gates.py::test_committed_schema_baseline_matches_the_current_code`
  gave `1 failed`. The edit was reverted.
- **risk-class-regression.** Editing `baselines/corpus-baseline.json` is caught one step earlier
  by `tests/phase4/test_corpus_baseline.py`. Checked locally: approval-spoofing was set to 2
  scenarios / 2 seeded true positives (committed: 1 / 1), then `uv run pytest -q --no-cov
  tests/phase4/test_corpus_baseline.py` gave `1 failed`. **The edit the brief suggested would
  not have produced the intended reason anyway.** That edit has the baseline claim a detection
  the corpus doesn't produce. The same edited baseline, run through `risk_class_gate` against the
  committed current metrics, returned `WITHIN_BASELINE` (not blocked). Both rates are 100% and no
  seeded finding is newly missed: the current class has zero false negatives. Every current class
  is at zero false negatives, so no baseline-only edit can make this gate block. It takes a worse
  corpus result, which the suite would catch first.

## Finding: the risk-class gate does not see a removed scenario

The local check above shows a gap. Suppose a seeded scenario is deleted from the corpus. The
committed baseline then still lists it (scenarios 2, TP 2), while the current metrics have
scenarios 1, TP 1. The risk-class gate passes, because it compares rates and newly-missed
findings, not scenario counts.

Today this is backstopped one step earlier. `tests/phase4/test_corpus_baseline.py` requires the
regenerated metrics to equal the committed baseline exactly, and requires 25 scenarios in total.
So CI as wired would block it at pytest. The gate on its own would not.

Not fixed here, because this WP records CI behaviour and does not change gate logic. Candidate
follow-up: have `compare_risk_classes` block when a class's scenario count falls below the
baseline (a reason like `SCENARIOS_REMOVED`), with a test on both sides.

## `pr-fast` wall time, from CI history

Command: `gh run list --workflow phase4.yml --limit 100 --json ...`, then
`gh run view <id> --json jobs` for each run, durations computed from the job's and each step's
`startedAt`/`completedAt`. `gh run list --status completed` returned 41 runs where the unfiltered
list showed 42 completed. The missing run (`44301776410`, a scheduled success) was fetched
separately and is included.

History: every completed run before this WP, 2026-10-18 to 2026-11-24. That is 1 pull_request,
4 push to main, and 37 schedule runs. All 42 `pr-fast` jobs succeeded.

| Scope | n | Measure | min | median | p95 | max |
| --- | --- | --- | --- | --- | --- | --- |
| History | 42 | `pr-fast` job | 952 s | 1,698 s | 1,898 s | 1,904 s |
| History | 42 | pytest step | 900 s | 1,609 s | 1,799 s | 1,810 s |
| History | 42 | smoke-demo step | 12 s | 20 s | 24 s | 25 s |
| History | 42 | corpus-baseline step | 21 s | 38 s | 43 s | 57 s |
| History | 42 | gates step | 1 s | 2 s | 3 s | 3 s |
| These 6 dispatches | 6 | `pr-fast` job | 1,078 s | 1,627 s | 1,821 s | 1,821 s |
| History + dispatches | 48 | `pr-fast` job | 952 s | 1,672 s | 1,898 s | 1,904 s |

p95 is nearest-rank. Script: a small local reader over the saved JSON dumps (not committed).

- **Against the proposed 10-minute (600 s) PR-lane ceiling (Phase 4 plan open question 3,
  WP4.1.3): not met in any of the 48 runs.** The fastest `pr-fast` job took 952 s, and the median
  is about 28 minutes. The full pytest suite is about 95% of the job (median 1,609 of 1,698 s).
  Phase 4 recorded this lane's CI wall time as "not measured". It is now measured, and it is
  roughly three times the proposed ceiling.
- **Against the 600 s smoke target: met in all 48 runs.** smoke-demo took 12–25 s. That matches
  the Phase 4 local figure of 11.72 s.
- The spread is mostly runner variance, not code. On a single commit, `6f3feb0`, 20 runs (1 push
  and 19 schedules) took 961–1,847 s for the `pr-fast` job. The six dispatches here ran
  concurrently on identical code, apart from one deselected test, and their pytest steps took
  1,021–1,732 s. A single run says little about this lane's speed.

Meeting the ceiling needs a decision, not a measurement. Either the PR lane stops running the
full suite (smoke + gates + a fast subset, with the full suite on push/nightly), or the ceiling
is restated. That decision belongs to the plan, not to this WP.

## Release lane: first observed in CI

`release` runs only on `workflow_dispatch` or `v*` tags. In all 42 history runs it was
`skipped`. **These six dispatches are the first time it ran in CI. It passed in all six.**

Control run ([45488892962](https://github.com/applea12X/ai-agent-purple-team/actions/runs/45488892962),
job `138781575284`), from its log:

| Step | Result | Time |
| --- | --- | --- |
| `purpleloop holdout-check` | **17/17 mutations denied**, base action permitted (positive control), holdout digest `84eec578…` (the one Phase 4 pinned) | 4 s |
| `purpleloop agent-demo` | **25 of 25 scenarios passed** (n=1 each) | 61 s |
| Attest, verify, export | `::notice::no CI attestation key; signing with an ephemeral key, recorded as such`; `ATTESTED suite-bundle bdeff8ee… key=ephemeral-local (ephemeral)`; `verify-bundle --attestation`: `valid: True, complete: True, scenarios: 25, key_provenance: ephemeral`; `EXPORTED runs=25` | 5 s |
| Whole job | success; `phase4-release-evidence` artifact 1.62 MB | 82 s |

The release job's wall time across all six dispatches was 63, 67, 69, 82, 88, and 111 s. All
six passed.

**The attestation is ephemeral.** The repository has no `PURPLELOOP_ATTESTATION_KEY` secret, so
the job took the ephemeral-key branch and recorded it as such. The CI-key branch of that step
(`--key-path`, `--key-id ci-release`) has still never run. That needs a repository secret, which
this WP was not authorized to create.

## Nightly-stochastic lane

Observed 43 times: 37 schedules in history and these 6 dispatches. It always ended the same way.
`PURPLELOOP_MODEL_ENDPOINT` is unset, so the step prints
`::notice::PURPLELOOP_MODEL_ENDPOINT is unset; stochastic lane skipped` and exits 0. The job
concludes **success** and uploads no evidence artifact, because `artifacts/` is empty.

The plan row 5.0.7 asks for this lane "observed at least once with a classified outcome". **Not
met: blocked on a hosted credential.** No `outcome.json` has ever been produced in CI, because
there is no hosted model endpoint. A recorded skip that shows as a green job is correct per the
workflow's design. It is also easy to misread as a passing stochastic run. Anyone reading the
Actions page should look at the notice, not the check mark.

## What this does and does not prove

**Does show:**

- The `pr-fast` job's wiring inside GitHub Actions. Phase 4 named this as untested. It covers
  step order, the gates step reading the JUnit file that step 9 wrote, reading the corpus metrics
  that step 11 wrote, reading the newest smoke bundle that step 10 built, failing the job on any
  blocked gate, and uploading evidence on failure.
- That CI blocks each of the five classes at the gate step, with every earlier step green, and
  passes when nothing is violated.
- That the critical-regression gate catches a real, otherwise-invisible regression in CI: a
  pinning test silently deselected.
- That the release lane works end to end on a hosted runner, with an ephemeral key.

**Does not show:**

- **Genuine violations for four of five classes.** scope-bypass, schema-drift, budget-failure,
  and risk-class-regression were shown by injection. Injection feeds a fabricated input to the
  same gate code over a real bundle. It does not show that a real kernel bypass or real over-budget
  run would reach the gate. As argued above, the suite would catch those at step 9 first.
- **That a pull request is blocked.** These were `workflow_dispatch` runs. The jobs, steps, and
  commands are the same as on `pull_request`. But whether a red `pr-fast` actually prevents a merge
  depends on branch protection and required status checks. That is a repository setting this WP
  did not read or change. No PR was opened.
- **A CI-key attestation.** It still needs a repository secret. See above.
- **A classified stochastic outcome.** It still needs a hosted endpoint. See above.
- **That the 10-minute PR-lane ceiling can be met.** It is not met today. See above.

## Commands and evidence

```
git push origin gate-proof/control gate-proof/scope-bypass gate-proof/critical-regression \
  gate-proof/schema-drift gate-proof/budget-failure gate-proof/risk-class-regression
gh workflow run phase4.yml --ref gate-proof/<branch>            # x6
gh run watch <id>
gh run view <id> --json jobs,headBranch,headSha,conclusion,url,event
gh run view --job <job id> --log
gh run list --workflow phase4.yml --limit 100 --json databaseId,status,conclusion,event,headBranch,headSha,createdAt
gh api repos/applea12X/ai-agent-purple-team/actions/runs/<id>/artifacts   # metadata only
uv run pytest -q --no-cov tests/phase4/test_gates.py::test_committed_schema_baseline_matches_the_current_code   # with an edited digest: 1 failed
uv run pytest -q --no-cov tests/phase4/test_corpus_baseline.py                                                   # with an edited baseline: 1 failed
```

The evidence is the six runs and their logs on GitHub, linked above, and the six `gate-proof/*`
branches on origin, which stay in place. The JSON dumps and logs used for the tables were saved
to a session scratch directory and are not committed. Artifacts were not downloaded.

## Status

**The Phase 4 red-branch checkpoint is closed as observed in CI.** One genuine violation and four
injected ones, each red at its own gate, plus a green control. `pr-fast` wall time is recorded
from 48 CI runs: it does not meet the proposed 10-minute ceiling, and smoke meets its 600 s
target. The release lane was observed for the first time and passed, with an ephemeral key.

Open:

1. PR-lane ceiling decision (restructure the lane or restate the target).
2. The risk-class gate's blind spot for a removed scenario (backstopped by the corpus-baseline
   test).
3. A CI attestation key secret, to exercise the CI-key branch.
4. A hosted endpoint, to get a classified nightly outcome.
5. Whether `pr-fast` is a required status check on `main` (repository setting, not checked).
