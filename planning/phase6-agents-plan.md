# Phase 6 implementation plan — red agents, a blue agent, and purple rounds

**Status: draft, not started.** This plan adds what the original concept doc listed as future
work: "multi-agent coordination where separate red and blue agents collaborate but maintain
distinct roles." It builds on the Phase 0–4 kernel and on two Phase 5 packages (WP5.0 and WP5.1).
It changes two PRD rules, listed in §1.3; those changes must be accepted in [PRD.md](PRD.md)
before any work package here starts. Where this document and the PRD disagree, the PRD wins.

---

## 0. Starting point

### What PurpleLoop is today

A sequential evaluation harness. For each authored scenario, `PurpleTeamRunner`
(`runtime/runner.py`) runs `provision → seed → clean → baseline attack → score → detect → defense
→ reset → replay → teardown`, and every target-facing action passes through `SafetyRuntime`.

- **Red side:** 48 authored scenarios plus `BoundedAttacker` (`control/attacker.py`), a
  deterministic, capped search over the typed argument corners of the agent-lane operations. It
  never writes free text. Its docstring anticipates "a model-driven attacker … behind the same
  caps"; that attacker does not exist yet.
- **Blue side:** none as an agent. Each scenario names one `defense_profile`. The runner checks it
  against the signed manifest, applies it through the fixture control plane, verifies the
  configuration, and replays. The 7 agent-lane profiles in `control/phase3_tools.py` are boolean
  configuration flags in the fixture. The harness never edits fixture source.
- **The model** in every real-model run so far (`qwen2.5:7b-instruct`) is the **target** — the
  supportlab assistant under attack — not an attacker or defender.
- **Attack payloads** are authored in `fixture/supportlab/agent_seed.py` and planted by the control
  plane at seed time. No attacker-facing operation writes content into the fixture.
- **Concurrency** exists only as a budget field (`authorization.py`, default 1; enforced in
  `control/budgets.py`). Runs are sequential.

### What this phase reuses unchanged

| Piece | Module | Role for agents |
| --- | --- | --- |
| Typed plan compiler | `control/plan_compiler.py` (`compile_step`) | Every red proposal is a `Step` and is compiled as untrusted data. A refusal is evidence, not an error. |
| Default-deny policy, budgets, kill switch | `control/policy.py`, `budgets.py`, `kill_switch.py` | Same caps apply per agent and per engagement. |
| Model plane | `adapters/model_provider.py`, model pins | Red and blue agents get their own pins, separate from the target's. |
| Offline model store | `adapters/offline_model.py` | Records every agent completion, so a discovered attack replays with no model. |
| Fixture control plane and reset | `runtime/fixture.py`, `fixture/supportlab/app.py` | Defense application, reset, state hashes. |
| Oracles, judge, gates | `scoring/`, `reporting/gates.py` | Success is still decided by state, never by an agent. |
| Shadow mode and risk approval | WP5.1 (planned) | Every new agent capability is admitted through it. |

### What this phase adds

Red agents that are LLMs, several at once; a blue agent that proposes fixes; and a deterministic
coordinator that runs red and blue in rounds against isolated fixture copies.

---

## 1. Objectives

1. **LLM red agents.** A model proposes attacks — tool calls and injection payloads — through the
   same typed compiler and policy as everything else. Successful attacks are frozen as replayable
   regression scenarios.
2. **Parallel red swarm.** Several red agents, each with a different tactic, each against its own
   disposable fixture instance, under one engagement budget and one kill switch.
3. **A blue agent.** Given a sealed finding, it proposes a fix at one of three tiers: choose
   defense profiles, write detection rules, or patch the fixture's source in a disposable copy.
4. **Purple rounds.** A deterministic coordinator runs red → triage → blue → verify → red
   re-attacks the fix, and reports what held.
5. **Honest measurement.** LLM red agents are compared against `BoundedAttacker` on equal budget.
   The blue agent is compared against the authored scenario → profile mapping. A fix counts only
   if replay, benign utility, the regression corpus, and holdout scenarios all agree.

### 1.1 The rule that holds the phase together

> Agents are untrusted components with more freedom of thought, not more authority. A red agent
> can propose any attack the typed vocabulary can express and nothing outside it. A blue agent can
> propose any fix its tier allows, and the kernel decides whether that fix is real by replaying the
> attack. No agent output is evidence, and no agent can approve, merge, or widen anything.

### 1.2 What "swarm" means here

N red workers (configurable, starting at 1 and capped by the signed manifest) plus one blue agent,
coordinated by deterministic code rather than an LLM. The agents never talk to each other
directly. They exchange sealed artifacts only: findings, verdicts, and round reports. That keeps
attacker-controlled content from flowing into one agent's prompt as instructions from another.

### 1.3 PRD changes this phase requires

| PRD text today | Proposed change | Why |
| --- | --- | --- |
| §3 "Do not autonomously patch the application." | "Do not autonomously patch any application outside a disposable fixture copy. Patch proposals are applied only to a disposable copy, verified by replay, and handed to a human; nothing is merged automatically." | Tier 3 of the blue agent (WP6.6). |
| §1 "apply only pre-approved defensive profiles" | "Apply only pre-approved defensive profiles to the shared fixture; agent-proposed configurations and patches run only in per-round disposable copies." | Tiers 1 and 3. |
| §8 Phase 5 list | Add Phase 6 as a separate optional track, admitted after WP5.0 and WP5.1. | Sequencing (§8). |

Everything else in PRD §2 and §3 stays: local and CI only, owned targets only, no autonomous
scope expansion, merging, deployment, risk acceptance, or evidence deletion.

### 1.4 Non-goals

An LLM coordinator; agents that pick their own targets; agent-to-agent free chat; testing a
website or application the user does not own or is not authorized to test; automatic merging of
blue-agent patches; fine-tuning; a leaderboard of attacker models; weakening any Phase 0–5
invariant.

---

## 2. The hard problems

### 2.1 Free-text payloads from a model, without free-text authority

`BoundedAttacker` deliberately never invents a free string. Prompt injection is free text, so an
LLM red agent must write it. The text is harmless to the harness only if it remains data.

**Design:**

- A red proposal has two parts: a typed `Step` (operation, tenant, resource, typed arguments) that
  `compile_step` compiles exactly as today, and an optional `payload` — a string with a hard length
  cap, delivered through a closed `injection_channel` enum (the existing `InjectionChannel` in
  `schemas/phase3.py`: `ticket`, `document`, `html`, `markdown`, `api-response`,
  `tool-description`, `memory`, `log`, `inter-agent`).
- Payloads reach the fixture **only through attacker-facing operations** — for example an org-b
  customer creating a ticket or uploading a document. These operations do not exist today and are
  added to the supportlab tool registry and fixture (WP6.3). The control plane never takes a
  payload from an agent; seeding stays authored.
- Exfiltration still targets owned canary sinks only. A payload that names an unregistered
  destination produces an intent the compiler refuses, which is recorded as evidence as it is today.
- Payload text is stored as evidence and passes through the existing redactor (which removes
  secrets and bearer tokens; it does not neutralize injection text). It is never placed in any
  trusted prompt, and the HTML report escapes it as it does all target content.

### 2.2 Stochastic search, deterministic evidence

An LLM attacker is sampled. The project's evidence model is replayable. These are reconciled by
recording, not by setting temperature to 0.

- Every red-agent completion is written as an `OfflineModelResponse` keyed by request digest.
- When an attack succeeds, the coordinator freezes a **generated scenario**: the minimal step
  sequence and payload that reproduced the security oracle, re-run once against a fresh fixture.
  It is stored with `origin: generated`, the red agent's pin, the round ID, and the offline
  responses needed to replay the target side when the target is also recorded.
- Generated scenarios enter `scenarios/generated/` only. Promotion into the labelled corpus is a
  human step (it reuses the WP5.0.8 `AdjudicationRecord`), never automatic.

### 2.3 A red agent needs a real target

The scripted stand-in target matches authored trigger phrases. A generated payload will not match
them, so LLM red agents against the stand-in measure nothing. Red-agent runs that count use a
real target pin (the local Ollama pin first). Stand-in runs exist only to test plumbing, and
reports label them that way.

### 2.4 Parallel runs that cannot see each other

Each red worker gets its own fixture instance: its own compose project name, network, ports,
state volume, and control-plane credential. The manifest grants a fixed pool of fixture assets
(`supportlab-w0` … `supportlab-wN`), and admission binds one worker to one asset. A worker can
compile steps only against its own asset, so cross-worker interference is a policy denial, not a
convention.

- **Budgets:** one engagement ledger, with per-worker sub-reservations carved out at start. A
  worker that exhausts its share stops. It cannot borrow.
- **Kill switch:** one switch owns every worker's tasks. Stop p99 ≤ 2 s is re-measured with N
  workers running.
- **Concurrency:** the existing `concurrency` budget field becomes the worker cap. Raising it from
  1 is a capability increase under WP5.1.
- **Local reality:** one local GPU serves the target and red pins in turn. "Parallel" on a laptop
  is mostly fixture-level parallelism with queued model calls. Reports state wall time and model
  queue time separately.

### 2.5 The blue agent reads attacker-controlled content

A finding's evidence contains the red payload. The blue agent must read it to fix the hole, so the
blue agent is exposed to prompt injection by design.

- Blue input is built by trusted code: the frozen regression, the oracle result, the policy
  decisions, the trace, and the payload in a quarantined, labelled block (the same pattern as
  `build_prompt` and ADR 0010).
- Blue output is narrow and typed per tier (§2.6). An injected blue agent can produce only a bad
  proposal, and verification rejects bad proposals.
- The blue agent has no tools during proposal. It cannot run code, read the repository, or call
  the fixture. It returns one typed document.

### 2.6 What a blue agent can propose

| Tier | Output | Applied where | Risk |
| --- | --- | --- | --- |
| 1 — Configure | A set of existing signed defense profiles (one or more, from `COMBINED_DEFENSES`) | The round's disposable fixture copy, through the existing `defense` control call | Low: no new behavior, only new combinations |
| 2 — Detect | A detection rule in a closed DSL: the oracle operator set (equality, existence, containment, count, delta) over typed telemetry and trace paths | The detector stage, alongside existing detectors | Low: rules are data and are evaluated, never executed |
| 3 — Patch | A unified diff restricted to an allowlist of fixture paths | A disposable git worktree, built into a fresh fixture image | Higher: the patched fixture runs new code. Needs a `code-exec` approval under WP5.1 |

Tier 3 path rules are enforced by the kernel, not the prompt:

- **Allowlist:** `src/purpleloop/fixture/supportlab/` and `targets/supportlab/`.
- **Denylist, checked after the allowlist:** anything under `control/`, `runtime/`, `scoring/`,
  `reporting/`, `schemas/`, `adapters/`; the fixture's control plane, telemetry, and state
  snapshot endpoints; seed data; tests; scenarios; policies; CI.
- Binary files, renames out of the allowlist, symlinks, and new dependencies are refused.
- The harness applies the diff with `git apply --check` in the worktree and never runs the
  patched code itself. The fixture image build and run happen in the existing fixture
  containment, with no egress.

### 2.7 A fix that games the test

A blue agent optimizing for "replay security verdict is false" has easy wrong answers. Each one
has a check:

| Gaming move | Check |
| --- | --- |
| Turn the feature off | Benign utility on the clean task and the whole utility corpus must not regress |
| Special-case the canary value or the exact payload | Holdout variants with fresh canary values per run and red re-attack variants (§2.8) |
| Break the state the oracle reads | Oracle paths, snapshot, and telemetry code are on the tier 3 denylist; state hashes still verified at reset |
| Fix one scenario, break three | The full regression registry runs against the patched copy |
| Claim success in prose | Blue output has no free-text verdict field; only the replay decides |

A fix is **verified** only when: the finding's replay security verdict is false; benign utility
holds; every registry scenario keeps its previous outcome or improves; holdout scenarios for the
same risk class pass; and the red re-attack round (§2.8) does not break it within its budget.

### 2.8 Re-attack: the purple part

After a fix is verified, red workers get one bounded round against the defended copy, told only
the risk class and that a defense exists, not what it is. A fix that survives k adaptive rounds
(pre-registered k, default 2) is reported as *held under adaptive attack*. A fix broken in round
r is reported with the breaking scenario frozen, and that scenario goes back to the blue agent.
The loop stops at a pre-registered round cap, budget exhaustion, or a held fix. It never runs
until no finding remains.

---

## 3. Contract changes

All additive and versioned, following the Phase 5 rule: older documents keep byte-identical
canonical bytes and digests, and `baselines/schema-digests.json` gains each new document.

### 3.1 Manifest 1.6 — `AgentGrants`

- `red_agents`: worker cap, red model pin IDs, per-worker budget share, allowed proposal kinds
  (`tool-args`, `payload`), allowed injection channels, payload length cap, rounds cap.
- `blue_agent`: blue model pin ID, allowed tiers (`configure`, `detect`, `patch`), tier 3 path
  allowlist digest, proposals per finding.
- `worker_assets`: the fixture asset pool, one per worker.
- `run_mode` from WP5.1 applies per agent kind, so red can run in `execute` while blue runs in
  `shadow`.

### 3.2 Capability delta extensions (WP5.1 `capability_delta`)

New increases: red proposal source `model`, payload generation, each new injection channel, worker
count above the approved one, each blue tier, tier 3 path allowlist widening, rounds cap above the
approved one. As in WP5.1, anything not recognized as a narrowing is an increase.

### 3.3 New documents

- `RedProposal` 1.0 — step, optional payload and channel, rationale, worker ID, round, completion
  digest.
- `GeneratedScenario` — Scenario 1.5 with `origin: generated`, `generated_by` (pin, round, worker),
  and the minimal reproducing steps.
- `BlueProposal` 1.0 — finding ID, tier, and exactly one of: profile set, detector rule, diff (with
  its digest and touched paths).
- `RemediationVerdict` 1.0 — proposal digest, each §2.7 check with its result, the overall
  verified flag, and re-attack outcome.
- `RoundReport` 1.0 — per round: proposals, refusals by reason code, findings (new versus already
  in the corpus), blue proposals, verdicts, budget spent per worker.

All agent-originated documents carry advisory provenance, so the existing gate input types reject
them as binding evidence (ADR 0009).

---

## 4. Work packages

### WP6.0 — Prerequisites and PRD amendment

| # | Task | Done when |
| --- | --- | --- |
| 6.0.1 | PRD amendment | The §1.3 changes are written into `planning/PRD.md` and `docs/prd.md`, with the reasoning, in one commit. |
| 6.0.2 | Prerequisites confirmed | WP5.0 (v1) and WP5.1 (shadow mode, risk approval, `capability_delta`) are closed by their own acceptance notes — or open question 1 is decided otherwise and recorded. |
| 6.0.3 | ADR: agents are untrusted planners | Records §1.1, §1.2, and §2.5 as the trust model for every agent. |

### WP6.1 — Contracts and admission

Files: `schemas/phase6.py`, `control/capabilities.py` (extend), `control/agents.py` (grant
checks), ADR.

| # | Task | Done when |
| --- | --- | --- |
| 6.1.1 | Manifest 1.6 and new documents | Round-trip and digest-stability tests; schema-drift gate covers them. |
| 6.1.2 | Capability delta extensions | Property test: every generated agent widening yields a non-empty delta. |
| 6.1.3 | Admission | A manifest with agent grants and no matching `RiskApproval` is refused with a reason code. |

### WP6.2 — One LLM red agent, tool arguments only

Files: `control/red_agent.py`, red prompt builder, `adapters/model_provider.py` (pin role).

| # | Task | Done when |
| --- | --- | --- |
| 6.2.1 | `ModelRedAgent` with the `BoundedAttacker` interface | It yields `Proposal`s; the runner accepts either attacker type through one protocol. |
| 6.2.2 | Feedback loop | The agent sees redacted observations of its previous attempts (quarantined block), bounded by turns and tokens. |
| 6.2.3 | Shadow first | WP5.1 shadow run: `ShadowReport` shows action classes reached and refusal rate; zero adapter calls. |
| 6.2.4 | Record and replay | Every completion is recorded; a red run replays from the offline store with identical proposals and hashes. |
| 6.2.5 | Baseline comparison | Same scenarios, same budget: LLM red agent versus `BoundedAttacker`, with findings, refusals, and cost. Pre-registered before the run. |

### WP6.3 — Payloads through attacker-facing channels

Files: `fixture/supportlab/app.py`, `control/phase3_tools.py`, new scenarios.

| # | Task | Done when |
| --- | --- | --- |
| 6.3.1 | Attacker-facing write operations | For example `ticket.create` and `document.upload` as an org-b customer, registered with typed args, a length cap, and tenant checks; each has a contract test. |
| 6.3.2 | Payload proposals | `RedProposal.payload` delivered only through those operations; a property test shows no payload ever reaches the control plane or a trusted prompt. |
| 6.3.3 | Generated scenario freezing | A successful payload attack is minimized, re-run on a fresh fixture, and written to `scenarios/generated/` with replay data. |
| 6.3.4 | Real target only | Red payload runs use a real target pin; stand-in runs are labelled plumbing-only in reports (§2.3). |

### WP6.4 — Parallel red swarm

Files: `runtime/swarm.py` (worker pool), compose profile for N fixture instances,
`control/budgets.py` (sub-reservations).

| # | Task | Done when |
| --- | --- | --- |
| 6.4.1 | Worker fixture pool | N isolated fixture instances; a test proves worker i cannot compile a step against worker j's asset. |
| 6.4.2 | Tactic assignment | Each worker gets one risk class or tactic from the signed grant; assignment is deterministic. |
| 6.4.3 | Shared budget and kill switch | Sub-reservations cannot be exceeded or borrowed; stop p99 ≤ 2 s measured with N = 4. |
| 6.4.4 | Triage and dedupe | Findings deduplicated by risk class and oracle result hash; each marked new or already in the corpus. |
| 6.4.5 | Scaling measurement | N = 1, 2, 4 on equal total budget: unique findings, wall time, and model queue time. |

### WP6.5 — Blue agent, tiers 1 and 2

Files: `control/blue_agent.py`, `scoring/detector_rules.py`, verification in `runtime/purple.py`.

| # | Task | Done when |
| --- | --- | --- |
| 6.5.1 | Blue input builder | Trusted code builds the input from a sealed finding; the payload is quarantined; a test greps the builder for raw-evidence concatenation and fails on a hit. |
| 6.5.2 | Tier 1: profile selection | Proposals are validated against `COMBINED_DEFENSES` and the manifest; applied only to a disposable copy. |
| 6.5.3 | Tier 2: detector rules | Closed DSL parsed into typed rules; scored for detection on the finding and false positives on clean runs and the benign corpus. |
| 6.5.4 | Verification | `RemediationVerdict` runs every §2.7 check; the verified flag is set by code only. |
| 6.5.5 | Baseline comparison | On the 25 authored agent scenarios: how often the blue agent picks a profile that verifies, versus the authored `defense_profile`. |
| 6.5.6 | Injection resistance | Evaluator red-team cases (as in `scenarios/evaluator-redteam`) aimed at the blue agent; each one fails verification or is recorded. |

### WP6.6 — Blue agent, tier 3 (sandboxed patches)

Requires a `code-exec` risk approval (WP5.1), as WP5.5 does.

Files: `control/patch_guard.py`, `runtime/patch_sandbox.py`, ADR.

| # | Task | Done when |
| --- | --- | --- |
| 6.6.1 | Path guard | Allowlist and denylist (§2.6) enforced on the parsed diff; property tests with traversal, renames, symlinks, binary files, and case tricks. |
| 6.6.2 | Disposable worktree and image | Diff applied in a fresh worktree; fixture image built and run under existing containment; the worktree is removed after the round, whatever the outcome. |
| 6.6.3 | Anti-gaming checks | Every §2.7 row has a test in which a deliberately gaming patch is rejected. |
| 6.6.4 | Hand-off | A verified patch is written to the bundle as a diff with its `RemediationVerdict`. It is never committed or merged by the harness. |
| 6.6.5 | Ground truth | Against the `f20f482` case (provenance enforced at the email sink), check whether the blue agent finds an equivalent sink-side fix rather than a prompt-only one. |

### WP6.7 — Purple rounds

Files: `runtime/purple.py` (coordinator), `phase6_cli.py` (`purple-round`, `purple-report`),
report section.

| # | Task | Done when |
| --- | --- | --- |
| 6.7.1 | Deterministic coordinator | red → triage → freeze → blue → verify → re-attack → report; the round order is a fixed state machine, not an LLM. |
| 6.7.2 | Stopping rules | Pre-registered round cap, budget, and held-fix rule (§2.8); every stop has a reason code. |
| 6.7.3 | Round report | `RoundReport` per round plus an engagement summary in the HTML report, with all agent output labelled advisory. |
| 6.7.4 | One-command demo | `make purple-demo` runs one full round on the local pins and produces a verified bundle. |

### WP6.8 — Optional: your own application as a target

Only for applications the user owns or is authorized to test, deployed to a staging or local
environment, with a signed manifest naming exact hosts.

| # | Task | Done when |
| --- | --- | --- |
| 6.8.1 | Target adapter contract | A typed operation registry for the external app, written by a human, with exact-host egress checks (reusing the Phase 0 per-hop authorization). |
| 6.8.2 | Read-only red first | Red agents limited to `read` action class; writes need a separate approval. |
| 6.8.3 | Advisory blue only | No fixture copy exists to patch, so blue output is tier 2 rules and written remediation advice, labelled advisory. |

---

## 5. Test plan

- **Unit:** proposal and payload schemas, path guard, detector DSL parser, sub-reservations,
  tactic assignment, stopping rules.
- **Property:** agent widenings always produce a capability delta; payloads never reach the control
  plane or a trusted prompt; diffs outside the allowlist are always refused; worker i never
  compiles against worker j's asset.
- **Contract:** each new attacker-facing operation; each agent's typed output is rejected rather
  than coerced when malformed.
- **Fault injection:** a red worker that hangs, a model that returns garbage, a patch whose image
  build fails, the kill switch during a parallel round, a budget running out mid-round.
- **Adversarial:** a compromised red model (the Phase 4 compromised-model property, applied to the
  red pin); prompt injection aimed at the blue agent; deliberately gaming patches.
- **Replay:** every frozen generated scenario replays with identical hashes from recorded
  responses.

## 6. Acceptance checkpoints

1. Zero out-of-scope executions, zero cross-worker actions, zero payloads on the control plane, and
   zero harness-executed patch code across the whole phase suite.
2. LLM red agent versus `BoundedAttacker` reported on equal budget, with the result stated whether
   or not the LLM wins.
3. At least one generated scenario frozen, replayed deterministically, and adjudicated by a human.
4. Blue tier 1 versus authored mapping reported on all 25 agent scenarios.
5. Every §2.7 gaming check proven by a rejected gaming patch.
6. One full purple round recorded end to end with its bundle verified.
7. Kill switch p99 ≤ 2 s with 4 workers.

## 7. Risks

| Risk | Mitigation |
| --- | --- |
| Red agents find nothing the corpus does not already cover | That is a result; report it. Tactic prompts per risk class and the feedback loop give the agent its best chance. |
| Blue tier 3 is too hard for a local 7B model | Tier 3 is optional; tiers 1 and 2 stand on their own. Try a hosted pin under a signed cost cap. |
| Local hardware serializes model calls | Report queue time separately; parallelism still isolates fixtures. |
| Scope creep toward public websites | Non-goal; WP6.8 requires ownership and a signed manifest with exact hosts. |
| Cost from many agents | Per-worker budget shares, signed cost caps, pre-flight estimate before any round. |
| Overfitting fixes to the fixture | Holdouts with fresh canaries, red re-attack, and the full registry (§2.7). |

## 8. Sequencing

```
WP5.0 close v1 ──> WP5.1 shadow + risk approval
                        └─> WP6.0 PRD amendment + ADR
                               └─> WP6.1 contracts + admission
                                      ├─> WP6.2 one red agent (tool args) ──> WP6.3 payloads ──> WP6.4 swarm ─┐
                                      └─> WP6.5 blue tiers 1–2 ──> WP6.6 blue tier 3 (code-exec approval) ───┴─> WP6.7 purple rounds
                                                                                                                  └─> WP6.8 own app (optional)
```

The red track (6.2 → 6.4) and the blue track (6.5 → 6.6) are independent until WP6.7, so they can
run in parallel. WP6.5 can be tested against the existing authored findings before any red agent
exists. WP6.6 and WP6.8 are optional; WP6.7 can close with tiers 1–2 only.

## 9. Open questions

1. **Must v1 close before any agent work?** The PRD says Phase 5 waits for v1, and this plan
   depends on WP5.1. *Recommendation:* close WP5.0 and WP5.1 first, and skip WP5.2–5.6 if time is
   short; they are independent of this phase.
2. **Which red pin?** *Recommendation:* the same local Ollama family for the first runs, then one
   hosted pin under a cost cap. Note that target and red sharing a model family may make attacks
   easier; state it.
3. **How many workers?** *Recommendation:* prove N = 1, then measure N = 2 and 4. Raise the cap
   only if the measurement shows a gain.
4. **Is tier 3 in scope for v1 of this phase?** *Recommendation:* yes as a work package, but
   optional at closing. It is the most impressive part and the riskiest.
5. **Who adjudicates generated scenarios?** *Recommendation:* the same approver as WP5.1; recorded
   honestly if that is the author.
6. **Which attacker-facing operations?** *Recommendation:* `ticket.create` and `document.upload`
   first, since they cover the two most common injection channels in the corpus.
