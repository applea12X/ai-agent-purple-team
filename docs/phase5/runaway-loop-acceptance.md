# Loose end 5.3: runaway-loop detection

Date: November 26, 2026

Measured on branch `worktree-agent-a354be7096663ffff`, from `phase-5` = `425e8b2`, with `phase-5`
merged in at `8d26986` (fast-forward), `d3e3b36` (WP5.2 matrix, merge `ff82ed8`), `fe7d52c`
(WP5.3 telemetry, merge `0293819`) and `9412aef` (WP5.5 codelab, merge `dd3bed4`), on the same local
macOS machine as WP5.0.1. Every number below comes from a command run in this session, written
next to it. No model was called. The looping target models and attacker models are scripted or
`httpx.MockTransport` stubs, and every run is on the in-process supportlab fixture.

Design: [ADR 0018](../adr/0018-runaway-loop-detection.md). Contracts: the 5.3 additions at the end
of [contracts.md](contracts.md).

## The claim checked first

Loose-ends row 5.3 said no detector exists. Searching `control/` and `runtime/` at `425e8b2`
(`grep -rn "runaway\|no-progress\|action-state" src docs planning`) found only the PRD sentence,
the threat-model row "Runaway or post-kill work" (budgets, wall time, task ownership), and the
loose-ends rows. What existed bounds *how much* a run does, not whether it repeats itself: plan
node and depth limits, the per-turn intent cap, attacker proposal and depth caps, budgets, and
wall time. ADR 0018 §Context tabulates each one. It was measured directly: with the guard
disarmed, a scripted model that asks for the same `email.send` four times per turn has all four
executed on every turn of every stage, and the run ends `PAIRED_EVALUATION`
(`test_a_disarmed_guard_records_nothing_and_lets_the_loop_run`).

## What was built

| Piece | Where |
| --- | --- |
| Detector (fingerprints, outcome digest, per-stage window, repetition and no-progress checks, latch, peaks) | `control/loop_guard.py` |
| Kernel wiring: boundary check after admission and before policy; outcome observation on policy deny, completion, and execution failure; latched refusal; `refused_step` for compile-refused and adapter-rejected attempts; host grant combined by `stricter_grant` | `runtime/runtime.py` (`SafetyRuntime`) |
| Fail-closed propagation for every source (plan, intent, refused or rejected intent, both attacker profiles) | `runtime/runner.py` (`submit`, `refused`, `RUN_STOP_REASONS`) |
| Shadow: would-be trips recorded and counted, nothing stopped | `runtime/shadow.py` (`run_batch`, `build_shadow_report`); `ShadowReport.would_be_loops` |
| Signed thresholds | `LoopGuardGrant`; `Phase5Grants.loop_guard`; `EvaluationMatrix.loop_guard` (`schemas/phase5.py`) |
| Matrix trials armed from the signed spec | `runtime/matrix.py::_run_trial`; `build_supportlab_runner(loop_guard=)` |
| Capability classification | `control/capabilities.py`: `phase5.loop_guard` is `not-capability` |
| Measurement script | `scripts/loop_guard_margins.py` |
| Codelab manifests armable | `runtime/codelab.py`: `codelab_manifest(loop_guard=)`, `approve(loop_guard=)` |
| Tests | `tests/phase5/test_runaway_loop.py` (56 tests) |
| Docs | ADR 0018; `architecture.md` "Phase 5: runaway-loop detection in the kernel"; `threat-model.md` "Phase 5 additions: runaway loops"; `incident-runbook.md` class 6; `contracts.md`; loose-ends row 5.3 |

## Measured results

**Detection on every action source** (`uv run pytest tests/phase5/test_runaway_loop.py`, armed
at N = 3, K = 8 unless stated). Each run ends `error` / `RUNAWAY_LOOP_DETECTED`. No target-plane
`RESULT` appears after the detection event, teardown completes, and the fixture is closed.

| Source | What looped | Where it stopped |
| --- | --- | --- |
| Model intent, executed | `email.send` ×4 in one turn | 3 executed. The 4th copy is the 3rd occurrence of one action-state hash (copy 1 moved the state) and is refused before dispatch |
| Model intent, refused at compile | `crm.update` on an unsigned resource ×4 | 3rd `TOOL_INTENT_REFUSED` (`refused: RESOURCE_NOT_SIGNED`) |
| Model intent, rejected by the adapter | malformed `refund.create` ×4 | 3rd `TOOL_INTENT_REJECTED` |
| Plan step | the attack step repeated 4×, N = 2 | in stage `attack` |
| Bounded attacker | same proposal ×6 | in stage `detect` |
| Model-driven attacker (shadow, approve, execute) | 4 identical proposals per round | stage `detect`, after 1 attacker-model call |
| Codelab (WP5.5) model intent | `analysis.run` ×4 and `report.publish` ×4, each in one turn, under the codelab manifest armed at 3/8 and approved for its exact delta | `repetition`, before the 4th copy |
| Evaluation-matrix trial | a real-pin row whose stub endpoint loops | every looping-pin trial `RUNAWAY_LOOP_DETECTED`, no anchor trial affected; with the spec unarmed, none is |
| Shadow | model-driven attacker, 4 identical proposals | `would_be_loops >= 1`, `adapter_calls == 0`, the walk continues past it |

**Margins on the legitimate corpus** (`uv run python scripts/loop_guard_margins.py`, all 25
agent scenarios, guard armed):

| Command | peak repetition | peak no-progress streak | trips | outcomes ≠ pin |
| --- | --- | --- | --- | --- |
| (defaults 64/256) | 1 | 0 | 0 | 0 |
| `--attacker` (64/256) | 1 | 3 | 0 | n/a |
| `--repeat-limit 2 --no-progress-limit 4` | 1 | 0 | 0 | 0 |
| `--attacker --repeat-limit 2 --no-progress-limit 4` | 1 | 3 | 0 | n/a |

So the tightest signable repeat limit (2), and a no-progress limit of 4, leave every agent
outcome equal to its pin in `baselines/regression-outcomes.json`. That covers status, the four
verdicts, the finding count and the oracle hash
(`test_an_armed_guard_leaves_every_agent_outcome_at_its_pin` asserts it). The recommended
engagement value for model-driven work is 3/8, roughly 2× and 2.5× the measured peaks plus one.
It is a recommendation, not a kernel default.

**Codelab corpus armed** (a scratch script, not committed, that runs `codelab.run_scenario`
for all 10 codelab scenarios under an approval armed at 2/4 and under the unarmed approval):
`codelab scenarios=10 limits=2/4 trips=0 differ_from_unarmed=0`. Status, reason, oracle hash
and finding count are equal for every scenario.

**Legacy unchanged.** `schema_digests()` equals the committed `baselines/schema-digests.json`.
The committed 1.4 nightly manifest still verifies against its committed key. `Phase5Grants`
without the grant has no `loop_guard` in its canonical bytes, and a pre-1.5 manifest cannot carry
it (`test_the_grant_is_additive_and_absent_from_legacy_bytes`,
`test_a_manifest_before_1_5_cannot_carry_the_grant`). The 48 per-scenario regression pins pass
in the full suite below.

**The detector cannot be removed or faked silently.** With `LoopGuard.boundary` and `observe`
stubbed to return nothing, the stop assertion fails (`test_a_removed_detector_...`). With a
detector that writes its event but lets the action proceed and never latches, the stop assertion
fails on the completed result after the event (`test_a_detector_that_records_but_never_stops_...`).
Editing or deleting `would_be_loops` in a stored shadow report fails `verify_shadow_bundle`.

**Properties** (hypothesis, 25 examples each, on a real `SafetyRuntime` over a signed 1.5
manifest). A plan of distinct actions with distinct outcomes never trips, at any limits 2–6 / 1–6.
A prefix followed by any cycle of 1–4 actions repeated `repeat_limit + 1` times always trips,
within `len(prefix) + len(cycle) × (1 + min(N, K))` actions. After the latch, the kernel alone
refuses the next action.

**Runbook class 6, drilled.** On a sealed suite bundle of a tripped agent run, made by a
scratch script, not committed, that runs the looping model through `evaluate_runner` exactly as
the lanes do:

- `purpleloop verify-bundle <suite>`: `VALID {'valid': True, 'complete': True, 'scenarios': 1}`.
- `purpleloop verify-ledger <run>/evidence.jsonl`: `VALID events=38`.
- `purpleloop audit-export <suite> out.json`: decisions `(32, policy, RUNAWAY_LOOP_DETECTED)` and
  `(37, termination, RUNAWAY_LOOP_DETECTED)`.
- `purpleloop locate-action <run> <digest>`: origin "model intent compiled at sequence 31".

The first runbook draft named a `--allow-partial` flag that `verify-bundle` does not have, and
a `locate-action <bundle>` path that has to be the run directory. Both were corrected before
commit.

## Quality gate and full suite

The detector worker's own full suite did not finish before hand-back. The integrated run on
`phase-5` at `1b23447`, which includes this work package and every other Phase 5 branch, is the
full-suite figure for it: `uv run pytest --junitxml=artifacts/junit-phase5-final.xml -q` gave
**1,307 collected, 1,299 passed, 8 environment-gated skips, 0 failed**, branch coverage
**91.99%**, in 1,725.87 s. `tests/phase5/test_runaway_loop.py` (56 tests) passed inside it. Lint,
format, and mypy were clean on the same tree. See [the Phase 5 index](../phase5-acceptance.md).

## What this does not show

- **No real model was run against the detector.** Every loop here is scripted. Whether a real
  model at temperature > 0 loops, and how close its legitimate runs come to 3/8, is unmeasured.
  The margins script can measure it on a pinned local model, but this worker may not call Ollama.
- **Disarmed by default.** Manifests 1.0–1.4, and every 1.5 manifest and matrix spec without the
  grant, have only the structural bounds they had before. Nothing yet *requires* the grant for
  `model-driven` sources or Phase 6 agents. ADR 0018 names that as the follow-up.
- **False negatives by construction, for reads.** A target that answers each repeated *read*
  with new bytes (a timestamp, a counter) advances the state digest every time, so neither check
  fires. Writes are immune: their outcome ignores the reply. Budgets
  and caps still bound such a run. A loop inside one adapter call, or across the runner's fixed
  stages, is out of scope.
- **Shadow over-approximates repetition** and does not evaluate no-progress. A would-be loop in
  a shadow report is a possible loop, not a measured one.
- **The chat lane (Phase 1)**: a schema-invalid `ToolIntent` still raises as a harness error, as
  before, rather than counting as a refusal. Plan steps and executed chat intents are covered.
- **Supportlab and Phase 1 lanes** were not run armed: their manifests (1.2, 1.1) cannot carry
  the grant, and no 1.5 builder exists for them. Their pinned outcomes are unchanged because the
  detector is disarmed there.
- **Overhead** (one extra JCS digest per action, two when it completes) was not measured
  separately.

## Defects found

None in earlier phases' code. Three defects in this worker's own drafts were caught by its tests
or its drill and fixed before the final commit.

- **A numbered acknowledgement disguised a repeated write as progress.** The first outcome
  digest of a completed write included its response. The codelab fixture numbers every
  publication (`{"publication": 1}`, `2`, `3`, ...), so `report.publish` ×4 never tripped.
  Root cause: write progress was judged by the reply rather than by the write. Fixed in `ecc25e4`:
  a write's outcome is its fingerprint and status. Pinned by
  `test_a_codelab_model_looping_on_one_tool_call_is_stopped[report.publish]` and the counter
  case in `test_a_write_outcome_is_bound_to_the_write_and_a_read_outcome_is_not`.
  The agent-lane margins were re-measured after the fix and are unchanged.
- Compile-refusal reasons were recorded as a constant instead of the compiler's reason code
  (`test_a_model_looping_on_a_refused_tool_call_is_stopped`).
- The runbook draft named a nonexistent `verify-bundle --allow-partial` flag (caught by the drill
  above).
