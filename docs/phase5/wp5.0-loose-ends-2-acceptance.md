# Loose ends, second pass (2.4, 4.12, 4.18, 4.23–4.25) — acceptance record

Date: November 25, 2026. Branch `worktree-agent-ab4d7e7c048d92d17`, from `phase-5` = `8f000e0`.
The loose-ends audit (`docs/phase5/loose-ends.md`) flagged seven items with no owner. This
worker closed six of them: rows 2.4, 4.12, 4.18, 4.23, 4.24 and 4.25. Row 5.3 (the runaway-loop
detector) belongs to another worker. No model was called. `runtime/runtime.py` was not edited.

| Row | Status | Commit | Evidence |
| --- | --- | --- | --- |
| 2.4 browser emergency stop | closed | `1e2ab24` | Measured below; `docs/phase5/evidence/browser-estop-*.json` |
| 4.12 retention and runbook | closed | `90be6c2`, `54758fc` | [drill-acceptance.md](drill-acceptance.md) |
| 4.18 WP4.0.1 revert checks | closed | — (scratch only) | Revert table below |
| 4.23 nightly browser workflow | closed | `81a17a2` | Nightly lane below |
| 4.24 nightly tracking issue | closed | `81a17a2` | Nightly lane below |
| 4.25 nightly scope from signed data | closed | `81a17a2` | Nightly lane below |

## 2.4 — browser-lane emergency-stop latency

**Method.** This follows Phase 0's method (`docs/phase0-acceptance.md`, "Kill-switch latency"):
1,000 independent trials, every counted trial waits until adapter activity has started, and the
time is taken from just before `KillSwitch.terminate()` to its return. Each trial is a whole
supportlab run of `bola-ticket-ui`, with a fresh fixture, kernel, and driver. The fixture's data
app holds the first `/ui/` page request open, so a browser page load is in flight at the kill.
`terminate()` returns only after the browser adapter's `finally` path has closed the session and
awaited `driver.shutdown()`. The trial then checks that the driver reports not alive and, for
Playwright, that every process descending from the test process before the kill has exited. It
also checks that the run re-raised the cancellation, that the summary reads `CANCELLED…`, and
that the fixture closed. A trial that fails any of these checks is never counted as stopped.
Pre-start trials are not counted.

Both drivers were measured. Playwright 1.58.0's Chromium build was already installed
(`~/Library/Caches/ms-playwright/chromium-1208`), so nothing was downloaded.

Commands, run at the final code, sequentially, under `caffeinate -i -s`, 2026-11-25
03:14:22Z–03:26:31Z:

```
uv run purpleloop browser-estop docs/phase5/evidence/browser-estop-html-form.json --trials 1000 --driver html-form
uv run purpleloop browser-estop docs/phase5/evidence/browser-estop-playwright-chromium.json --trials 1000 --driver playwright-chromium
```

| Driver | Trials counted / fully stopped | p50 | **p99** | max | p99 to the runner's return | Wall |
| --- | --- | --- | --- | --- | --- | --- |
| `html-form` (in process) | 1000 / 1000 | 6.58 ms | **8.67 ms** | 12.13 ms | 12.41 ms | 55.96 s real |
| `playwright-chromium` (Chromium 145.0.7632.6) | 1000 / 1000 | 29.42 ms | **119.26 ms** | 340.21 ms | 261.65 ms | 673.06 s real |

The required p99 is at most 2,000 ms, and both drivers meet it. The Playwright trials saw 5
browser processes per trial (`browser_processes_seen` = 5,000), and none survived any stop. The
"p99 to the runner's return" column includes the runner's own teardown, evidence write, and, for
Playwright, uvicorn shutdown. It is reported in each record beside the stop and is not the
emergency-stop figure. The figures in the table are read from the committed records.

**An earlier run, not committed.** The first Playwright 1,000-trial run, at an earlier revision
of the same module whose timed window was unchanged, read p99 **60.01 ms** (max 183.09 ms; 685.55
s real). The committed run overlapped other work on this machine (an in-process nightly-lane run
and a smoke demo), and the difference between the two runs is about that size. Neither run is a
quiet-machine figure. Both are far under the ceiling.

**Fails when faked.** `tests/phase5/test_browser_estop.py` recomputes p99, max, and the
run-return p99 from the per-trial samples each record ships with. It requires at least 1,000
counted trials, all fully stopped, positive and varying samples, a run return at or after each
stop, and, for Playwright, at least one browser process per trial. Writing a record with
`stop_p99_ms` changed to 1.0 makes the test fail (`assert 1.0 == 12.3738`), as does writing back
the Phase 2 shape `{"measured": true}` (`KeyError: 'schema'`). Both were checked by hand on a
temporary edit, then restored. The live tests show:

- the timed window includes the browser teardown: with a driver whose shutdown takes 80 ms,
  every sample is at least 80 ms;
- a driver that survives its own shutdown gives `trials_fully_stopped == 0`;
- a browser that never starts is recorded as not started and not counted.

A 3-trial live Playwright test runs under `PURPLELOOP_CONTAINER_TESTS=1`. It passed here
(`1 passed`). It is skipped in the default suite.

**Observed, not fixed.** Every Playwright trial logs `Future exception was never retrieved …
net::ERR_ABORTED` (1,000 times in the first run's log). The cancelled `page.goto` leaves a
Playwright-internal future whose abort is never awaited. It is noise, not a leak: the processes
are gone. Fixing it would touch `PlaywrightSession` (shared adapter code), so it was left for the
author.

**What this does not show.** The figures are from one macOS arm64 machine, not CI. The kill
lands during navigation, and a kill during `fill`, `click`, or artifact capture was not
separately timed. As in Phase 0, this measures the kernel's cancellation path to a stopped
browser. It does not cover an uncontrolled remote process (row 0.1).

## 4.18 — behavioural revert checks for the WP4.0.1 fixes

**Method.** The commit `8f000e0` was archived (`git archive`) into a scratch directory outside the
repository. Each fix's *behaviour* was reverted there by hand, with every name it introduced
(`PinnedModelLabel`, `RUN_STOP_REASONS`, `ActionFailed`, `describe_intent_arguments`) kept
importable. The fix's pinning tests were then run. Nothing was reverted in this branch, and no
revert was committed. After the last check, `diff -r` of the scratch `src/` against a pristine
extraction was empty. The unmodified scratch copy passed the four pinning files: `33 passed in
8.32s`.

Command for each: `uv run pytest -q --no-cov <files>` in the scratch copy.

| Fix | Behaviour reverted (only) | Pinning tests run | Result | How they fail |
| --- | --- | --- | --- | --- |
| `b7fe527` (prompt) | `SYSTEM_PROMPT` no longer appends `describe_intent_arguments()` | `test_intent_schema_prompt.py`, `test_agent_cli.py` | **7 failed**, 11 passed | `AssertionError: the system prompt does not describe crm.update's arguments` (and one per operation), plus the closed-choice and round-trip tests |
| `b7fe527` (Inspect label) | `model_label()` always returns `purpleloop/offline`; pin metadata dropped | same | **2 failed**, 16 passed | `assert 'purpleloop/offline' == 'purpleloop-pin/ollama/qwen2.5:7b-instruct'` |
| `c557c80` (runner) | `intent_action` delegates to the fail-closed `action()` | `test_intent_failure.py` | **3 failed**, 8 passed | `ActionFailed: TARGET_OUT_OF_SCOPE`; `AssertionError: EXECUTION_FAILED`; run status `'error'` |
| `c557c80` (kernel detail) | the failure detail is never set | same | **3 failed**, 8 passed | `assert None == 'ValueError: fixture transport status 403'`; `KeyError: 'detail'` |
| `6322c03` | both `raise ActionFailed(...)` sites raise `RuntimeError(...)` | same | **5 failed**, 6 passed | `assert 'RuntimeError' == 'EXECUTION_FAILED'`; `RuntimeError: BUDGET_EXCEEDED` / `KERNEL_STOPPED` / `WALL_TIME_EXCEEDED` escape |
| `f20f482` (provenance sink) | the `retrieval_provenance and leaves and tainted(user)` clause removed | `test_provenance_sink.py` | **2 failed**, 2 passed | `assert 'ok' == 'denied'`; `assert 'true' == 'false'` |

Every revert fails on an assertion about behaviour, and none fails with an `ImportError`. The
audit's import-time failure came from removing whole source hunks, names included. Since the
existing tests already pin the behaviour, no new Phase 5 test was added for 4.18.

## 4.23–4.25 — the nightly lane

`phase4.yml` was not edited; its nightly job still hard-codes `agent-indirect-ticket`.
`phase5.yml` gains a `nightly` job (schedule `17 4 * * *`, plus `workflow_dispatch`) with
`permissions: contents: read, issues: write`. It is the only job with issue write, and a test
asserts that.

- **Scope from signed data (4.25).** The job's first step is `purpleloop nightly-scope`. It
  verifies `scenarios/nightly/manifest.json`, a Manifest 1.4 signed under key id
  `nightly-scope` and checked against the committed `scenarios/nightly/authorization-public.pem`.
  It then prints `nightly_scope`. The manifest was signed once, by
  `uv run purpleloop nightly-scope-sign --scenario agent-indirect-ticket --scenario bola-ticket
  --scenario bola-ticket-ui --repetitions 5 --rotation "…"`, which reported `SIGNED e4513222…
  valid_until=2027-11-25T03:17:58+00:00 (ephemeral key, discarded)`. The private key was never
  written to disk. Changing the scope therefore means re-signing, and a new public key shows up
  in review. The job names no scenario path and no repetition count, and a test asserts that
  too. An edited scope fails `INVALID_SIGNATURE`. An expired one fails `EXPIRED_MANIFEST`, runs
  nothing, and files an issue.
- **Browser workflow (4.23).** `purpleloop nightly-lane` runs the scope's supportlab scenarios:
  the shared API/browser pair `bola-ticket`/`bola-ticket-ui` on the served fixture with real
  Chromium, after `playwright install --with-deps chromium` on the pinned `ubuntu-24.04`. These
  need no credential, so they run every night. It also runs the agent scenarios through
  `agent-run --repetitions <signed> --judge --attacker` against `PURPLELOOP_MODEL_ENDPOINT`.
  When no endpoint is configured, each agent scenario is a recorded `skip-no-credential`.
- **Classified outcome and issue (4.24).** Every outcome is classified in `nightly.json` using
  the closed Phase 4 vocabulary. `purpleloop nightly-issue` runs `if: !cancelled()`. If the night
  had any outcome other than `pass` or `skip-no-credential`, or recorded no outcome at all, it
  comments on the open issue titled `Nightly lane: non-pass outcome`, or creates that issue. It
  does this with `gh` and `GH_TOKEN: ${{ github.token }}`. The code never reads or passes a
  token.

**Run offline here:** `env -u PURPLELOOP_MODEL_ENDPOINT uv run purpleloop nightly-lane
--output-dir $SCRATCH/nightly-inproc --browser-fixture in-process` gave `bola-ticket
[supportlab]: pass PAIRED_EVALUATION`, `bola-ticket-ui [supportlab]: pass PAIRED_EVALUATION`,
and `agent-indirect-ticket [agent]: skip-no-credential STOCHASTIC_LANE_UNAVAILABLE`, with exit 0.
`nightly-issue --dry-run` then reported `no issue: every outcome is pass or a recorded
skip-no-credential`. `tests/phase5/test_nightly_lane.py` (20 tests) covers:

- scope verification and every refusal;
- the real in-process browser run;
- the signed repetitions reaching the agent executor;
- issue-body rendering;
- create versus comment versus nothing, against a fake `gh` executable;
- the workflow's wiring.

**Not run:** the scheduled job itself. It was not dispatched (it would only have recorded the
agent scenarios as skipped) and nothing was pushed. `gh` was never called against GitHub, and
the served/Chromium nightly path ran only through the 1,000 Playwright emergency-stop trials,
not through `nightly-lane` itself. Sizing the agent subset is still WP5.0.2. The scope file
expires on 2027-11-25, and an expired scope files an issue rather than running silently.

## Defects found in earlier phases' code

1. **Scope and budget gates compared evidence across runs** (Phase 4, `reporting/gates.py`).
   Root cause and fix are in the drill record. Fixed in `54758fc` and pinned by
   `tests/phase5/test_gate_ledger_segments.py`. Before the fix, a bypass in one run was masked by
   another run's permit for the same digest; 37 of 100 executed digests in a real suite are
   shared.
2. **Incident runbook steps that were wrong or could not be followed**, and **retention gaps**:
   suite files fell due while their runs were held, `bundles` had two durations, and model
   replies also live in the repo-life ledger. All are listed in the drill record and fixed in
   the documents or the new commands.
3. **Phase 2 browser emergency-stop record held no figure.** Now measured, as above.

## Quality gate

Commands and results, at the final commit:

- `uv run ruff check . && uv run ruff format --check . && uv run mypy`: all passed (97 source
  files).
- `uv run pytest -q --no-cov tests/phase5`: **306 passed, 1 skipped** in 121.99 s. The skip is
  the Playwright live test, gated on `PURPLELOOP_CONTAINER_TESTS=1`.
- `uv run pytest -q -x --no-cov tests/phase4 tests/phase3`: see "Full suite" below.

## Full suite

Recorded below when run.

## What this does not show

- Row 5.3 (no-progress loop detector) is not addressed here.
- The nightly job has never run in CI. Its parts were tested one by one, offline.
- The emergency-stop figures are local and single-machine, as stated above.
- The drill injected its incidents. See the "what this does not show" section of the drill
  record.
