# ADR 0018: Runaway-loop detection on action-state hashes, armed by a signed grant

Status: accepted for Phase 5 (loose end 5.3).

## Context

PRD §7 lists, under the safety kernel: "Detect repeated/no-progress action-state hashes and stop
runaway loops." The loose-ends audit (`docs/phase5/loose-ends.md`, row 5.3) found no such
detector. A search of `control/` and `runtime/` at `425e8b2` confirms it. What did exist bounds
how *much* a run can do. Nothing notices that a run is doing the *same* thing:

| Existing control | What it bounds | What it does not see |
| --- | --- | --- |
| Acyclic plan, `phase1.max_nodes` / `max_depth` (`plan_compiler`, runner dynamic-intent check) | Number of plan nodes plus compiled intents per run | Whether those nodes repeat each other |
| `phase3.max_tool_intents_per_turn` (agent adapter and runner) | Intents taken from one model turn | Four identical intents in one turn are all executed |
| `phase3.max_attacker_proposals` / `max_attacker_depth` (runner `proposal_stream`, shadow `run_batch`) | Proposals and rounds of the adaptive attacker | A model-driven attacker proposing the same refused action each round |
| Signed budgets, tokens, cost, wall time (`BudgetLedger`, `asyncio.timeout`) | Total spend and time | Whether anything was achieved with it |
| Kill switch | Operator stop | Needs an operator |

Every one of these is a ceiling. A captured or confused model can spend the whole ceiling on a
loop, and the run ends `BUDGET_EXCEEDED` or reaches its caps looking like an ordinary run. The
gap matters now: the WP5.1.6 model-driven attacker, the WP5.2 matrix's real-model rows, and the
Phase 6 agents are the first sources whose action sequence is not fixed in advance.

## Decision

### 1. Where: one boundary in the kernel, every source

The detector is `control/loop_guard.py`, owned by `SafetyRuntime`. It is consulted at the
point in `SafetyRuntime.run` right after manifest and capability admission and before policy.
Every target-plane action from every source passes through that point: plan nodes,
model-emitted tool intents, bounded-attacker proposals, model-driven-attacker proposals, and the
matrix's trials. A model or attacker attempt that never becomes an action also counts. That is
a step the plan compiler refused, or an intent the agent adapter rejected before it was typed.
It reaches the same guard through `SafetyRuntime.refused_step`. A model asking again and again
for a forbidden tool call is the commonest loop, and it never reaches `run`.

The fixture control plane (`adapter == "control"`) is exempt. Its calls come only from
`FixtureController` on a fixed lifecycle (a `Step` cannot name that adapter), they repeat by
design (`snapshot`, `telemetry`), and teardown must still run after a trip.

### 2. What is hashed, and why that state

- **Action fingerprint.** SHA-256 over the JCS form of adapter, operation, method, target (URL,
  tenant, resource), side-effect class, credential handle, and arguments. `action_id`,
  `idempotency_key` and `budget` are left out. The first two are per-run identity: a model that
  re-asks under a fresh node id must hash the same. The budget is invisible to the target.
  Refused steps hash their typed fields the same way, without `node_id` and `depends_on`.
  Rejected intents hash by the operation name they gave.
- **State digest.** A digest chained over the *distinct* outcomes the kernel has recorded in the
  current window. An outcome is the status and the redacted result data of a completed action:
  the same bytes the `RESULT` event carries, minus latency. A completed write's outcome also
  includes its fingerprint, so a different write is always a change and a repeated one is not.
  A denied, failed, or refused action is no change.
- **Action-state hash** = H(fingerprint, state digest before the action).

The kernel cannot see the target's database. The fixture's state hash exists only where the
runner snapshots it, at leg boundaries, so it cannot say whether the last intent changed
anything. Snapshotting per action would add control-plane calls, and with them ledger events,
which would move every pinned replay hash. The ledger's semantic hash changes with every event
appended, so it never shows "no change". The outcome the kernel itself recorded is the only
per-action state signal it already holds. It is deterministic wherever the ledger is (pinned
replays require that), and it costs one JCS digest per action. The cost of the choice is a false
negative: a target that answers each repeat with fresh bytes, such as a timestamp, defeats both
checks. Signed budgets and caps still bound such a run.

### 3. Checks and windows

- **(a) Repetition.** The N-th occurrence of one action-state hash in a window is refused before
  dispatch, so at most N−1 occurrences execute.
- **(b) No progress.** The K-th consecutive action in a window that does not advance the state
  digest trips once its outcome is known. That action has executed, and its result stands in the
  ledger.

A trip records one `POLICY` event, decision `deny`, reason `RUNAWAY_LOOP_DETECTED`, carrying the
check, the limit, the observed count, the fingerprint, the state digest and the action-state
hash. The guard then **latches**: the kernel refuses every later target-plane action of the run
with the same reason, so a runner that ignored the trip still could not continue. The runner
raises `ActionFailed(RUNAWAY_LOOP_DETECTED)` on the latch, from whichever source tripped it. The
run ends `error` / `RUNAWAY_LOOP_DETECTED`, teardown runs, and a partial bundle is written. The
`POLICY` and `TERMINATION` events both appear in the audit export's decision record.

**One window per stage.** The runner's stages are a fixed sequence that no action can change.
The paired design deliberately repeats the clean task: after a verified reset in the replay leg,
and again for utility under attack. A repeat across stages is the method working, not a loop.

### 4. Who sets N and K: signed data only

- **Manifest 1.5:** `phase5.loop_guard: LoopGuardGrant | None` with `repeat_limit` (2–64) and
  `no_progress_limit` (1–256). The upper bounds keep a signed value meaningful.
- **Evaluation matrix:** `EvaluationMatrix.loop_guard`, same type. Matrix trials run on lane
  manifests 1.3, which cannot carry the grant. The spec is signed and verified before any trial,
  and `run_matrix` passes its grant to each trial's runtime as a host grant. If a manifest grant
  and a host grant are both present, the stricter of each limit applies.

`capability_delta` classifies the grant as **not-a-capability**, like `budgets` and
`stop_conditions`. It is a stop rule: it can only end a run sooner. Without it, a run has
exactly the v1 structural bounds the baseline approved.

### 5. Default: disarmed, with nothing recorded

Without a grant (every manifest 1.0–1.4, every 1.5 document and matrix spec signed before the
field existed), the guard computes nothing and records nothing. Three reasons:

1. The rule "no existing outcome or pinned hash changes" forces it. Any default threshold
   either sits above the structural bound, which is the same as off, or sits below it and can
   change a pinned outcome.
2. Those manifests were signed by someone who never agreed to a loop rule. A kernel-chosen
   threshold would be unsigned authority.
3. Measurement says the legitimate corpus does not need one. Over all 25 agent scenarios with
   the guard armed, the peak repetition count is 1 and the peak no-progress streak is 0, or 3 with
   the bounded attacker. At limits 2/4 every outcome equals its pin
   (`docs/phase5/runaway-loop-acceptance.md`).

The new fields default to `None`, and canonical bytes exclude `None`. So every existing manifest,
shadow report, and matrix spec keeps its bytes, its signature, and its digest, and
`baselines/schema-digests.json` is unchanged.

### 6. Shadow mode reports and stops nothing

In shadow nothing executes, so no outcome exists and the state digest stays at the window
origin. Repetition is still evaluated. A would-be trip is recorded as `RUNAWAY_LOOP_WOULD_TRIP`
(decision `would-deny`, event schema 1.2.0), the walk goes on, and `ShadowReport.would_be_loops`
counts the trips. It is recomputed from the ledger by `verify_shadow_bundle`, and absent when
zero. Because the state never advances, this over-approximates: an execution whose results
changed the state between repeats would not trip. No progress is not evaluated in shadow, since
every action would count. Shadow never latches.

## Consequences

- An armed run that loops ends with a distinct, evidenced reason instead of spending its budget.
  The cost is one fingerprint and one outcome digest per action.
- The thresholds are a signed engagement decision. The acceptance note recommends 3/8 for
  model-driven work: roughly 2× and 2.5× the measured peaks plus one. It is not a kernel default.
- Not covered: a loop whose every repeat returns new bytes. A loop across stages, which the
  runner's fixed stage sequence rules out. A loop inside one adapter call, such as a browser
  page's own requests, which subresource authorization and budget charging cover. The chat
  lane's (Phase 1) `ToolIntent` validation failure, which still raises as before rather than
  counting as a refusal.
- Follow-up, not done here: a later manifest version could *require* a `loop_guard` whenever
  `proposal_source` is `model-driven`, and for Phase 6 agents. That is a validator change on a
  new schema version, not something to retrofit onto 1.5.
