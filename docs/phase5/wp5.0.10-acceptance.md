# WP5.0.10 — Per-scenario regression pinning

Date: November 24, 2026

Measured on branch `worktree-agent-acd8f62c4fc3b4b3e` (from `phase-5` = `a79f185`) on the same
local macOS machine as WP5.0.1. Every number below comes from a command run in this session. No
model was called.

## What changed

Phase 4 pinned all 48 findings to three corpus-level tests, so when one failed the
critical-regression gate could only say that one of 5, 18, or 25 findings regressed
(`docs/phase4-acceptance.md`, "Regression registry"). The standing rule forbids editing those
tests, so the per-scenario pins are new tests next to them:

- `tests/phase5/test_regression_pinning.py::test_pinned_finding[<scenario_id>]`: one node ID
  per corpus scenario, 48 in all. Each runs its scenario once through
  `src/purpleloop/runtime/pinning.py`. That module builds the runner the way the lane's corpus
  fixture does, using the same `build_runner` / `build_supportlab_runner` / `build_agent_runner`
  helpers with a fresh key and fixture per run. Each test asserts, for its one scenario, what
  the lane's corpus test asserts: paired-loop verdicts, equal seed hashes, mitigation credited,
  teardown, zero unauthorized replay side effects, the ground-truth label, bundle verification,
  no planted secret in the bundle, a permit before every completed action, and no open budget.
  It also asserts the supportlab completeness and resource tolerances and the phase1
  susceptibility check where they apply. The agent corpus test asserts only aggregate recall of
  at least 0.9. The per-scenario pin is stricter: each agent scenario must detect its own
  finding.
- `baselines/regression-outcomes.json`: the recorded outcome of each scenario (status, four
  verdicts, finding count, run-independent `oracle_hash`). Every pin asserts that its run
  reproduces its row. To re-pin, run `scripts/repin_regression_outcomes.py` in a reviewed
  commit.
- `scenarios/regression-registry.json`: every entry's `test` is now its own per-scenario node
  ID. The old corpus test is kept as a new optional field, `corpus_test`. The change is
  additive, and 1.4 registries without the field still load.
- `critical_regression_gate` (`reporting/gates.py`): an entry may name several pinning tests.
  Every one of them that appears in the report must have passed, and at least one must appear.
  So a per-scenario failure names exactly one finding. A corpus-test failure still blocks every
  finding it pins. A report that holds only the corpus tests, which is the shape of the Phase 4
  CLI test's fixture, is still judged. If neither appears, the gate blocks as
  `REGISTRY_TEST_NOT_RUN`, as before.
- The Phase 4 dangling-reference check strips `[param]` and confirms only that the function
  exists, so it would accept a misspelt case. `test_no_registry_reference_dangles_at_parameter_granularity`
  closes that gap by asking pytest itself (`--collect-only`) for the node IDs of every
  referenced file. `test_a_bad_parameter_id_is_detected` shows the function-level check
  accepting `test_pinned_finding[agent-indirect-tickte]`, while the collected-ID check and the
  gate (`REGISTRY_TEST_NOT_RUN`) both refuse it. The Phase 4 test is unchanged and still passes.

## Measured

| Item | Command | Result |
| --- | --- | --- |
| The three corpus tests alone | `uv run pytest -q --no-cov --durations=5 <the three node ids>` | 3 passed in **33.76 s** (24.03 + 7.50 + 1.60 s call) |
| The new module | `uv run pytest -q --no-cov --durations=8 tests/phase5/test_regression_pinning.py` | **64 passed in 43.43 s** (a second run: 45.33 s) |
| Its per-test sum | same with `--durations=0`, summed | 48 pins: 27.0 s agent + 12.1 s phase1/supportlab; the other 16 tests: 1.9 s (the 3 lane aggregates reuse the pinned runs and add ≈ 0) |
| Outcome determinism | `scripts/repin_regression_outcomes.py` logic run twice in separate processes, outputs `cmp`'d | identical; 48 of 48 `passed`, baseline `true`, replay `false`, 1 finding |
| Clean gate | `uv run purpleloop gates <smoke bundle> --junit <junit of the module> --risk-current baselines/corpus-baseline.json` | exit 0, `pass critical-regression: REGISTRY_TESTS_PASSED — 48 covered finding(s)` |
| CLI injection | same, `--inject critical-regression` | exit 1, `REGISTRY_TEST_FAILED — failed pinning tests for: bola` |
| A real regression | `"agent-indirect-ticket"` deleted from its defense's applicable set in `control/phase3_tools.py`, the pins run to JUnit, then the edit reverted (`git checkout`) | pytest: 1 failed, 47 passed. Gate: exit 1, `failed pinning tests for: agent-indirect-ticket` (**exactly one finding**) |
| The same regression, Phase 4 registry | corpus tests run under the same edit, gated with `--registry-path` = the pre-change registry | `failed pinning tests for:` the first 20 of the 25 agent findings (the detail is capped at 20) |
| Phase 4 regression and gate tests | `uv run pytest -q --no-cov tests/phase4/test_regression_registry.py tests/phase4/test_gates.py tests/phase4/test_phase4_cli.py` | 47 passed |

**Runtime cost.** The pins add about 41 s of test time. That is about 1.2× the corpus tests
they refine, because they also verify bundles and ledgers for the agent lane, which the agent
corpus test does not. Against WP5.0.1's 1,039 s suite that is about 4%. The full suite at the end of this branch took
1,078.20 s (`docs/phase5/loose-ends.md`), 39 s more than WP5.0.1.

## What this does not show

- The corpus tests and the pins run the same scenarios twice in a full run. Removing that
  duplication would mean editing Phase 1–3 tests, which the standing rule forbids.
- `oracle_hash` is pinned exactly. A deliberate fixture change (for example a WP5.0.2
  application fix) moves it, and such a change must re-pin in the same reviewed commit. That
  is the intended friction, not a defect.
- The pins prove the gate names one finding per failed scenario. They do not make a corpus-level
  failure any more specific when the per-scenario tests did not run.
- CI has not observed any of this. The red-branch observation is WP5.0.7.

## Status

**WP5.0.10 closed.** All 48 registry entries name their own node ID. One injected regression
names exactly one finding. The Phase 4 granularity caveat is closed.
