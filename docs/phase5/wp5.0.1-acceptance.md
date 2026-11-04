# WP5.0.1 — Full measured suite run at the phase base

Date: November 4, 2026

Measured at `main` = `ab66ab0` (clean working tree) on a local macOS machine: Darwin 27.2.0,
arm64, 11 cores, Python 3.12, running on battery. Docker was not running. Every number below
comes from a command that was actually run. No model was called.

## Result

| Item | Phase 4 record | This run |
| --- | --- | --- |
| Tests collected | — (475 by `--collect-only` at `f3f247b`) | **475** |
| Passed | 435 | **472** |
| Skipped | 3 | **3** (the same three) |
| Failed / errors | 0 | **0 / 0** |
| Branch coverage | 88.73% | **89.40%** (floor 85%) |
| Suite time, awake | 753 s | **1,039 s** (pytest's own clock) |
| CPU time | not recorded | **1,021 s** (996 s user + 25 s sys) |

**The 475 is now a pass count.** 472 passed + 3 skipped = 475, all 475 collected tests,
confirmed by the JUnit report (`tests=475 failures=0 errors=0 skipped=3`).

Quality gate, same commit: `ruff check` passed, `ruff format --check` passed (188 files),
`mypy` strict passed (80 source files).

### The three skips

All three are gated on infrastructure, as in Phases 3 and 4:

- `tests/phase1/test_isolation.py::test_container_denies_egress_and_cross_plane_credentials`:
  explicit container acceptance lane
- `tests/phase2/test_supportlab_isolation.py::test_container_isolation_and_cross_plane_credentials`:
  explicit container acceptance lane
- `tests/phase3/test_seed_materialize.py::test_the_agent_surface_hash_is_identical_on_postgres_and_sqlite`:
  needs `PURPLELOOP_CONTAINER_TESTS=1` and `PURPLELOOP_TEST_POSTGRES_DSN`

## Wall time, and why there are two numbers

`/usr/bin/time` reported **1,767 s real** for the run. pytest reported **1,039 s**. The
difference, about 728 s, is time the machine spent asleep.

- pytest measures with a monotonic clock that, on macOS, does not advance while the system
  sleeps. `/usr/bin/time` measures wall-clock time, which does.
- The power log (`pmset -g log`) shows the lid was closed during the run. The machine slept and
  made repeated short dark wakes from 23:39 to 23:58 local, with full wakes at 23:58:09 and
  00:00:54. The run spanned 23:39:32–00:08:59 local (05:39:32–06:08:59Z).
- CPU time (1,021 s) is within 2% of pytest's 1,039 s. The suite is CPU-bound on one core, so
  whenever it was awake, it was running.

**The awake time to quote is 1,039 s.** This was not an uninterrupted run. It ran on battery
with the lid closed for part of it. It should not be compared directly with Phase 4's 753 s,
which was 37 fewer tests on an unrecorded power state.

The slowest tests, which together are about 70% of the awake time:

| Test | Time |
| --- | --- |
| `phase3/test_agent_acceptance.py::test_agent_lane_replay_determinism` | 159.6 s |
| `phase3/test_compromised_model.py::test_a_captured_model_reaches_no_out_of_scope_action` | 158.4 s |
| `phase4/test_advisory_probe_isolation.py::test_the_whole_corpus_passes_with_the_attacker_on` | 92.7 s |
| `phase3/test_agent_acceptance.py::test_evidence_completeness_over_the_agent_corpus` | 72.2 s |
| `phase2/test_supportlab_acceptance.py::test_100_isolated_runs_no_cross_run_leak` | 72.1 s |
| `phase3/test_agent_acceptance.py::test_token_and_cost_estimate_against_actual` | 68.4 s |
| `phase3/test_agent_corpus.py::test_corpus_metrics_over_the_whole_agent_corpus` | 65.4 s |
| `phase4/test_corpus_baseline.py::test_corpus_baseline_command_reproduces_the_committed_baseline` | 63.9 s |
| `phase1/test_loop.py::test_same_configuration_replay_100_trials` | 58.7 s |

## The Phase 4 stalled run, re-checked

Phase 4 recorded a run that was unfinished after about 92 minutes of wall time with about 9
minutes of CPU, cause not determined.

**Reproduced in form, and explained for this session.** The first attempt at this measurement
(started 05:00:11Z) showed the same pattern. Its log stopped growing at 23:05 local, inside
`tests/phase3/test_agent_acceptance.py`. After 30.5 minutes it had used 5.6 minutes of CPU. The
power log shows `Entering Sleep state due to 'Clamshell Sleep'` at 23:05:33. The machine stayed
asleep until a lid wake at 23:30:31. When it woke, a stack sample showed the process running
normally at ~100% CPU under the coverage tracer, not blocked. That attempt was stopped and its
log kept (`artifacts/wp5.0.1-suite-slept.log`). The run measured above is the second attempt.

**Not confirmed for the original Phase 4 run.** This machine's power log only goes back to
October 28, 2026, so the September 15 event cannot be checked. Its signature matches system
sleep: wall time far above CPU time, in a suite this run shows is CPU-bound whenever the machine
is awake. No evidence of a deadlock or hang in the code was found. This is the most likely
explanation, not a proven one.

**What to do about it.** Quote pytest's own duration together with user + sys CPU time, as
here. A run on battery with the lid closed will sleep despite `caffeinate` or the desktop app's
keep-awake. For a clean uninterrupted wall time, run on AC power with the lid open.

## Commands and evidence

```
uv sync --frozen
uv run ruff check .
uv run ruff format --check .
uv run mypy
uv run pytest --collect-only -q --no-cov
caffeinate -i -s /usr/bin/time -l uv run pytest --junitxml=artifacts/wp5.0.1-junit.xml --durations=30
```

Local evidence files. `artifacts/` is git-ignored, so these are not committed:

- `artifacts/wp5.0.1-suite.log`: full output of the measured run, including the `/usr/bin/time` block
- `artifacts/wp5.0.1-junit.xml`: JUnit report (475 tests)
- `artifacts/wp5.0.1-start.txt`: UTC start and end
- `artifacts/wp5.0.1-suite-slept.log`, `artifacts/wp5.0.1-start-slept.txt`: the first attempt,
  interrupted by lid sleep

## Status

**WP5.0.1 closed.** Pass count, skips, coverage, and suite time are recorded. The 475-collected
figure is reconciled to a pass count. The Phase 4 stall is reproduced and explained as system
sleep for this session, and recorded as likely but unconfirmed for the original run.

Open: a run on AC power with the lid open would give an uninterrupted wall time. This is
optional, because the awake time above already serves the purpose.
