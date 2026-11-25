# WP5.1 — Shadow mode and risk approval

Date: November 25, 2026

Measured on branch `worktree-agent-ae88efd5bd629bf3b` (from `phase-5` = `3fd1fd9`, with
`phase-5` merged in at `8f000e0` and again at `61bbeb5`) on the same local macOS machine as
WP5.0.1. Every number below comes from a command run in this session, written next to it. No
model was called: every attacker model is the offline `ScriptedAttackerModel` or a local stub,
and the target model is the offline `ScriptedAgentModel`.

Design: [ADR 0014](../adr/0014-shadow-mode-and-risk-approval.md). Contracts: the §3 types in
`schemas/phase5.py` plus the WP5.1 additions listed at the end of [contracts.md](contracts.md).

## What was built

| Task | Where |
| --- | --- |
| 5.1.1 `capability_delta` | `control/capabilities.py`; `CapabilitySurface`, `CapabilityBaseline` in `schemas/capability.py` |
| 5.1.2 Shadow run mode | `SafetyRuntime.is_shadow` and the suppression branch in `runtime/runtime.py`; `EventKind.SHADOW_SUPPRESSED` (event schema 1.2.0); `runtime/shadow.py::ShadowRunner`, `CountingAdapter` |
| 5.1.3 `ShadowReport` | `runtime/shadow.py::build_shadow_report` (pure, from the verified ledgers), `verify_shadow_bundle` (recomputes it) |
| 5.1.4 Signing and verification | `control/approvals.py::grant_approval`, `sign_baseline`; reuses `control/phase5_signing.py` unchanged |
| 5.1.5 Admission enforcement | `control/approvals.py::ApprovalAdmission`, called per action by `SafetyRuntime` and once per run by `SafetyRuntime.admit` from `PurpleTeamRunner.run`; `AGENT_LANE.manifest_versions` = `{1.3.0, 1.5.0}` |
| 5.1.6 Model-driven attacker | `control/attacker.py::ModelDrivenAttacker`, `require_attacker_authorized`; `adapters/scripted_attacker.py`; `PurpleTeamRunner.proposal_stream` |
| Approved baseline | `baselines/capability-baseline.json` + `capability-baseline-public.pem`, built by `runtime/governance.py` |
| CLI | `purpleloop shadow-run`, `approve`, `approval-check`, `capability-baseline [--check]`, `approver-keygen` (`phase5_cli.py`) |
| CI | `phase5.yml` job `governance`; `make governance-check` |
| Extra: gate fix | `risk_class_gate` blocks `SCENARIOS_REMOVED` (`reporting/gates.py`; methodology rule 6) |

## Checkpoints (plan §6, rows for 5.1)

| Checkpoint | Threshold | Measured | Command |
| --- | --- | --- | --- |
| Shadow never executes | 0 adapter calls | **0** dispatches across the full 25-scenario agent corpus, bounded attacker: 650 actions decided and suppressed, 200 proposals. **0** fixture requests, **0** target-model calls in the same run | `uv run pytest -q --no-cov tests/phase5/test_shadow_mode.py` → 16 passed (`test_the_full_agent_corpus_in_shadow_dispatches_nothing`) |
| | | **0** dispatches across the agent corpus with the model-driven attacker; the attacker model was consulted and every call is in the ledger | same file, `…with_the_model_driven_attacker…` |
| | | **0** dispatches and **0** fixture requests across the 5 `phase1` and 18 `supportlab` scenarios with their real adapters (http, tool, chat, browser, control), shadowed by the runtime flag under v1 manifests | same file, `test_legacy_lanes_shadow_through_every_real_adapter` |
| | | Fault injection: all **69** registered `(adapter, operation)` pairs across the four tool registries (`mock_read`, `http`, `tool`, `chat`, `browser`, `control`, `agent`), with a policy that permits everything and an adapter that fails the test if touched: 69 of 69 suppressed, adapter touched **0** times, credential never resolved — through the runtime flag, a shadow manifest, and both. Also: concurrent submission, an execute manifest under a shadow runtime, the paired runner handed a shadow manifest, and 25 generated plans | same file |
| | | The CLI on the full agent corpus: `adapter dispatches 0 (report adapter_calls 0)`, 650 suppressed, 600 unreachable, 11.71 s (bounded); 600 suppressed, 600 unreachable, 275 proposals / 250 rejected, 12.39 s (model-driven) | `uv run purpleloop shadow-run <dir>` and `… --proposal-source model-driven`, wall time from `/usr/bin/time -p` |
| Uncovered increase refused | 100% of generated widenings | Every one of the **6** increase kinds refused (`CAPABILITY_INCREASE_UNAPPROVED`) at admission, and again end to end: the paired runner ends the run with that reason, 0 fixture requests, 0 model calls, and the refusal is an `admission`/`deny` decision in the audit export — 6 of 6 | `uv run pytest -q --no-cov tests/phase5/test_approval_admission.py` → 44 passed |
| | | Property: any non-empty set of increase kinds is refused without an approval (40 examples per run); only the exact delta is admitted (40); narrowing and non-capability changes never need one (40). The delta properties: any composed widening is exactly the union of its kinds (60), any narrowing is empty (60), narrowing elsewhere never hides a widening (60), invariant to order and JSON round-trip (60). 30 explicit seeds: 32 passed each time | `… -k "any or only or narrowing or invariant" --hypothesis-seed=$i` for i in 1..30 |

## Other measured results

| Item | Result | Command |
| --- | --- | --- |
| Capability delta, unit | 22 widenings each produce exactly their one kind; 23 narrowings and non-capability changes produce none; an unclassified field produces all six; the classification names exactly the current manifest fields | `tests/phase5/test_capability_delta.py` → 61 passed |
| Tamper and coverage refusals | each with its own reason code: not found, shadow report missing, ambiguous (2 approvals), approval for no increase, superset and different deltas, a further widening (`APPROVAL_MANIFEST_MISMATCH`), expired, not yet valid, untrusted key, forged signature, approver key = attestation / manifest / baseline key, other baseline, shadow report of another surface, other engagement, untrusted or edited baseline, unconfigured admission | `test_approval_admission.py` |
| Approval expiring mid-run | first action completes; at `expires_at` the next action is denied `APPROVAL_EXPIRED`, recorded as an `admission` deny | `test_an_approval_expiring_mid_run_fails_closed_at_the_next_action` |
| The report is unfakeable | Patching the runtime to dispatch in "shadow" makes the report impossible to build (`adapter_calls` validation error) and the fixture counter goes above 0; an unmeasured count fails closed; an edited report or a truncated ledger is refused by `verify_shadow_bundle` | `test_shadow_mode.py` |
| Unreachable steps | equals an independent count from the scenarios (per model turn: 4 intent slots on the agent lane; the clean turn counted twice for the utility-under-attack pass; both legs): 600 on the agent corpus | `test_the_full_agent_corpus_in_shadow_dispatches_nothing` |
| Model-driven attacker | closed-set validation of every candidate; decisions-only feedback; own caps and the runner's signed caps both binding; refused unless signed (`PROPOSAL_SOURCE_NOT_SIGNED`, `ATTACKER_PIN_NOT_SIGNED`, `ATTACKER_MODEL_ENDPOINT_NOT_SIGNED`, `ATTACKER_CAPS_EXCEED_SIGNED`); execute without an approval is refused before the attacker model is asked (0 calls); with an exact approval the paired run on `agent-tool-misuse` **passed**, proposals went through the kernel, and the scope gate saw no bypass | `tests/phase5/test_model_driven_attacker.py` → 14 passed |
| CLI sequence | `approver-keygen` (0600) → `shadow-run --proposal-source model-driven` → `approve` → `approval-check`: `ADMITTED CAPABILITY_INCREASE_APPROVED delta=['proposal-source-change']`; without the approval `REFUSED CAPABILITY_INCREASE_UNAPPROVED` (exit 1); 2 h later `REFUSED APPROVAL_EXPIRED` (exit 1); `approve` on the v1-surface shadow `REFUSED NO_CAPABILITY_INCREASE`. The same sequence for `--action-class code-exec` admits `['new-action-class']` | local run at `ae6b387`; `tests/phase5/test_governance_cli.py` → 6 passed |
| Committed baseline | `VALID baseline 8ed9d8e7663c73472aa95440eeb552776176a07951b314a876bcd0ea851c8ff0 key=v1-baseline-ephemeral (ephemeral); matches the v1 lane manifests`; every v1 lane manifest has an empty delta against it; an edit fails its signature; no private key in `baselines/` | `uv run purpleloop capability-baseline --check`; `tests/phase5/test_capability_baseline.py` → 6 passed |
| `SCENARIOS_REMOVED` | the WP5.0.7 case (2/2 → 1/1) blocks; additions and new classes do not; an existing regression keeps `RISK_CLASS_REGRESSION`; the committed corpus is still `WITHIN_BASELINE`; removing one scenario from any of the 13 classes blocks | `tests/phase5/test_risk_class_scenarios_removed.py` → 4 passed |
| Paired runs with the bounded attacker, unchanged | 25 of 25 agent scenarios `passed`, no policy, budget, or result denial in any ledger | `run_offline_scenario(path, out, attacker=True)` over the corpus (scratch script) |

FULL_SUITE_PLACEHOLDER

## The baseline and the keys, in plain words

- **The baseline** is the union of the four v1 lane manifests' capability surfaces, signed with
  an ephemeral key generated inside `sign_v1_baseline` and discarded when it returned. It was
  never written to disk. Its `approver` field says "the project's single author". It proves
  the surface was signed once and has not been edited since. It does not prove anyone reviewed
  it. The plan asks for it to be signed at the v1 tag; v1 is not tagged, so that is still open
  (WP5.0.12).
- **The approver keys** used in this note were generated by `purpleloop approver-keygen` into the
  session scratchpad, used once, and the private key deleted at the end of the script. In the
  tests every key is generated in memory. In CI the key is generated per job in `$RUNNER_TEMP`.
- **Who held them:** the project's single author held the baseline key (for the length of one
  function call), the manifest keys, and the approver keys. Key separation is enforced — the
  approver key may not be the manifest key, an attestation key, or the baseline key — but it
  compares key ids. **Separate keys are not separate people.** No second person holds an
  approver key, so no approval in this repository is an independent human decision.

## What this does not show

- **That shadow output predicts execution.** Nothing executes, so nothing responds: 600 of the
  agent corpus's tool-intent slots were unreachable in each shadow run, and no oracle, detector,
  or judge ran. A shadow report says what the kernel would have decided about the actions it
  could see, not what a model would have done with responses it never got.
- **The would-be budget is the target plane's reservation only.** Tokens a real model would have
  consumed are not in it (the offline agent operation reserves 0 tokens), and the attacker
  model's tokens are charged to the run budget but are not part of `would_be_budget`.
- **Anything about a real attacker model.** The model-driven profile ran only on the scripted
  attacker; its proposal mix (for example 50 `PROPOSAL_UNKNOWN_OPERATION` refusals in the
  model-driven shadow run) is the script's, chosen to exercise refusals. Running it against a
  real model is WP5.2's job and needs an approval covering `proposal-source-change`.
- **That every increase is captured.** The closed enum covers the plan's six kinds. Budget and
  spend changes, relaxed stop conditions or evidence requirements, model-pin changes, and judge
  changes are classified as not capabilities (ADR 0014 lists each); a manifest can change them
  without an approval. A field added later is caught (every kind) only because a test pins the
  classification to the current fields.
- **Compile-time refusal reasons are lossy.** `compile_step` refuses with sentences, not reason
  codes; the report records those as `PLAN_REFUSED` (100 in each agent-corpus shadow run).
- **CI observation.** The `governance` job was not observed in CI from this branch; it was not
  pushed. The same commands were run locally (above).
- **A schema-drift reference for the baseline.** `CapabilityBaseline` has no entry in
  `baselines/schema-digests.json`; adding one means editing the pinned §3 contract test.

## Defects found

- **Shadow walk fidelity (this WP, fixed before landing).** The first version of the shadow walk
  continued after a kernel-denied accepted proposal, where `PurpleTeamRunner.action` ends the
  run. Fixed in `8665e8f`; on the committed corpus no accepted proposal is denied at run time,
  so no measured number moved.
- **The mid-run expiry test used an import-time clock (this WP, fixed).** It failed once in an
  8-minute phase 3–5 run (684 passed, 1 failed) because the module's `NOW` fell before the
  fixture-built manifest's `valid_from`. Pinned to the test's own instant in `b5da217`.
- **Risk-class gate blind to removed scenarios (WP5.0.7 finding, fixed).** Root cause and fix
  above; pinned by `tests/phase5/test_risk_class_scenarios_removed.py`.
