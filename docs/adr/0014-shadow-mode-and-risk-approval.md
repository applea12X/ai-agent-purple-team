# ADR 0014: Shadow mode by not dispatching, and signed approval of an exact capability delta

Status: accepted for Phase 5 (WP5.1).

## Context

Phase 5 is the first phase allowed to make the harness more capable rather than more
trustworthy (plan §1). The PRD requires every autonomy or action-class increase to be run in
shadow first and then admitted only under a signed risk approval. Two things make that hard
(plan §2.2). A shadow that leaks — some path still reaches an adapter — is worse than no shadow,
because it is trusted. And "every increase needs an approval" is unenforceable if whoever writes
the manifest also decides what counts as an increase.

The §3 contracts already existed when this work started: manifest 1.5 (`Phase5Grants`),
`RiskApproval`, `ShadowReport` (with `adapter_calls: Literal[0]`), the `CapabilityIncrease`
enum, and `control/phase5_signing.py`. This ADR records how WP5.1 uses them.

## Decision

### 1. Shadow is not dispatching, decided in the kernel

`SafetyRuntime.run` runs admission, capability admission, policy, the kill-switch check, and the
budget reservation exactly as it does for an execution. Then, if the run is in shadow, it records
a `SHADOW_SUPPRESSED` event with the decision that would have applied, finalizes the reservation
as consumed, and returns `status="suppressed"`. It never creates the adapter task, never resolves
a credential, never builds the target guard. No adapter checks a flag; adapters never learn that
shadow exists.

A run is in shadow when **either** the runtime was constructed with `shadow=True` **or** the
manifest is 1.5 with `run_mode: shadow`. Neither can take the other out of shadow. The
`ShadowRunner` always forces `shadow=True`.

The reservation is consumed rather than released so that a shadow run exhausts its budget at
the point an execution would; the report's `would_be_budget` is that consumption.

`SHADOW_SUPPRESSED` is a new `EventKind` value. It is additive: no earlier event carries it, and
every earlier kind keeps its value. Shadow events are written at event schema `1.2.0`; 1.0 and
1.1 events are unchanged, so every recorded seed hash and replay fingerprint is unchanged.

### 2. The shadow runner mirrors the paired runner and measures itself

`runtime/shadow.py::ShadowRunner` walks each scenario through the steps `PurpleTeamRunner.run`
takes: admission, plan compilation, every control-plane call, both legs, the
utility-under-attack pass, and the attacker's proposals, submitting each action to the runtime.
It ends a walk exactly where a paired run fails closed (a planned, control, or accepted-proposal
action that does not complete, or a run-level stop). It wraps the runtime's adapter in a
`CountingAdapter` and writes the measured dispatch count into the ledger.

The `ShadowReport` is derived from the verified ledgers by a pure function
(`build_shadow_report`); `verify_shadow_bundle` recomputes it and refuses a bundle whose stored
report disagrees. A non-zero, or unmeasured, dispatch count makes the report impossible to build,
because `adapter_calls` admits only `0`.

**Representativeness is stated, not solved.** Nothing executes, so nothing responds. Every
tool-intent slot a model turn reserved (1 per chat turn, `max_tool_intents_per_turn` per agent
turn) depends on a response nothing produced; each is recorded as `SHADOW_UNREACHABLE` and
counted in `unreachable_steps`. Oracles, detectors, and the judge are not evaluated.

### 3. The capability delta is a closed, total, fail-closed function

`control/capabilities.py::capability_delta(approved, requested)` projects each manifest onto a
`CapabilitySurface` (`schemas/capability.py`) and compares axis by axis. Only an exact narrowing
(subset, lower cap, segment-aligned narrower path prefix, more exclusions, a resource restriction
added) is not an increase. The mapping onto the closed enum:

| Increase kind | Axes |
| --- | --- |
| `new-action-class` | declared `phase5.action_classes`, classes implied by `allowed_side_effects`, classes registered for an operation (`OPERATION_ACTION_CLASSES`, empty in v1; WP5.5 registers its code-execution operation) |
| `new-adapter-or-operation` | `allowed_adapters`, `allowed_operations − denied_operations`, `allowed_methods`, `(credential handle, operation)` pairs, `phase2.browser_assets` |
| `new-target-fixture` | each target asset (scheme/host/port equal, path prefix within, tenants ⊆, resolved addresses ⊆, resource restriction kept), `(tenant, resource)` ownership pairs, every approved exclusion still present |
| `widened-egress` | `egress_hosts`, `model_endpoints`, `phase3.model_assets`, `phase2.subresource_origins`, `phase5.telemetry` |
| `raised-attacker-caps` | `max_attacker_proposals`, `max_attacker_depth`, and the caps on the other untrusted proposer — the model under test: `max_tool_intents_per_turn`, `max_agent_steps`, `phase1.max_nodes`, `phase1.max_depth` |
| `proposal-source-change` | `phase5.proposal_source` (`bounded-search` < `model-driven`; absent is `bounded-search`) |

**Not capabilities** (each named in `FIELD_CLASSIFICATION`): identity and validity
(`engagement_id`, `owner`, `approvers`, `key_id`, the three timestamps, `signature`,
`schema_version`); spend (`budgets`, `token_budget`, `cost_microusd_budget`,
`max_browser_contexts`, `nightly_scope`, `matrix_scope` — each has its own signed control);
evidence and safety rules (`retention_days`, `redaction_required` and `data_classification`,
both fixed by the schema, `required_evidence`, `stop_conditions`, `cleanup_procedure`,
`stop_on_error`, Phase 4 retention and attestation keys); model pins and the judge (the model is
the system under test; what it may *do* is bounded by the operations and caps above);
`defense_profiles`; `credential_handles` (subsumed by the scope pairs); `ownership_seed`
(carried by the ownership pairs); the database and model credential handles, which the schema
already forbids as attack credentials; `run_mode` and `risk_approvals`.

**Unknown is every increase.** A test asserts the classification names exactly the current
fields. At run time, a field in neither list that is set to anything but its default makes
`capability_delta` return all six kinds, so only an approval naming all six could cover it.

### 4. The approved baseline is a dedicated signed record, not an empty approval

`RiskApproval.capability_delta` must be non-empty, so "an approval of nothing" cannot express a
baseline. `CapabilityBaseline` (`schemas/capability.py`) is a signed record of one
`CapabilitySurface`, with `derived_from`, `approver`, and `key_provenance`, signed with the
ADR 0002/0012 Ed25519/JCS construction. It is not in `CONTRACT_VERSIONS` and has no schema-drift
reference digest (adding one means editing a pinned §3 test; recorded as a follow-up).

The committed baseline (`baselines/capability-baseline.json`, public key beside it) is the union
of the four v1 lane manifests' surfaces: Phase 1 demo (1.1), supportlab (1.2), offline agent
(1.3), and the agent lane signed for the local Ollama origin `http://127.0.0.1:11434` (1.3, the
WP4.0.1 and nightly configuration). It was signed with an **ephemeral** key discarded after
signing — the same honest precedent as the Phase 4 release attestation. It proves the surface
was signed once and not edited since; it proves nothing about who approved it. The plan says the
baseline is signed "once at the v1 tag"; v1 is not tagged yet (WP5.0.12), so re-signing it with a
held key at the tag is WP5.0.12's job. `purpleloop capability-baseline --check` verifies the
signature and that the v1 lane builders still produce exactly this surface.

### 5. Admission: empty delta, or one exact approval, or refusal

For a manifest 1.5 in `execute` mode, admission (`control/approvals.py::ApprovalAdmission`)
checks, in order, and refuses with the first failing reason code:

1. the baseline's signature and key separation (`BASELINE_*`);
2. the delta against the baseline; empty and no approval named → `NO_CAPABILITY_INCREASE`;
3. an approval named for no increase → `APPROVAL_DELTA_MISMATCH`; a delta with none named →
   `CAPABILITY_INCREASE_UNAPPROVED`; more than one named → `APPROVAL_AMBIGUOUS`;
4. the named approval and the shadow report it names are on hand (`APPROVAL_NOT_FOUND`,
   `APPROVAL_SHADOW_REPORT_MISSING`);
5. `verify_risk_approval`: trusted key, signature, window, engagement, capability surface, key
   separation, shadow report digest (reason codes from `control/phase5_signing.py`);
6. the approver key did not sign the baseline; the approval names this baseline
   (`APPROVAL_BASELINE_MISMATCH`); the shadow report was produced on **this manifest's shadow
   twin** — the same manifest with `run_mode: shadow` and no approvals
   (`APPROVAL_SHADOW_NOT_THIS_SURFACE`);
7. `approval.covers(delta)`: exact set equality (`APPROVAL_DELTA_MISMATCH`).

**Exactly one approval covers a delta.** Combining several would let a delta be assembled from
grants each made for a different increase; an approval binds one manifest surface anyway.

Admission runs on every action (so an approval expiring mid-run fails closed at the next action)
and once per run in the runner's admission stage, where it is recorded as an `ADMISSION` event
either way; a refusal ends the run with its reason code and appears in the audit export.
A 1.5 manifest with no admission configured is refused (`APPROVAL_ADMISSION_UNCONFIGURED`).
Shadow manifests are admitted with their delta recorded and no approval required. **Manifests
1.0–1.4 are the v1 surface**: no check runs and nothing new is recorded for them.

`AGENT_LANE.manifest_versions` is widened to `{1.3.0, 1.5.0}`. A 1.5 manifest validates only
with Phase 3 grants, so it is agent-lane shaped; the Phase 1 and supportlab lanes are unchanged.

### 6. The model-driven attacker is a proposal source behind the same caps

`ModelDrivenAttacker` (`control/attacker.py`) asks a model for proposals in rounds. Operations,
tenants, and argument schemas are closed sets from trusted code; each candidate is validated
before it becomes a `Proposal`, and every refused candidate is recorded with its reason. The
model is shown the kernel's *decisions* on earlier proposals and never any target content. Its
caps come from the signed manifest and the runner enforces them again independently. Using it
requires `phase5.proposal_source: model-driven`, a signed model pin, and — for a networked
model — a signed model endpoint (`require_attacker_authorized`). Because that field is a
`proposal-source-change`, the profile runs in shadow without an approval and in execute only
with one. The first real use of the approval path in this repository is this profile, on the
offline `ScriptedAttackerModel`.

## Consequences

- A shadow run cannot silently execute: the runtime does not dispatch, the runner measures, and
  the report type refuses a non-zero count. `tests/phase5/test_shadow_mode.py` fakes the leak
  (patches the runtime to dispatch) and the report cannot be built.
- An increase is a fact computed from signed data, not a claim in a manifest. The manifest
  author can still choose not to declare an action class; an operation registered as code
  execution derives its class anyway, and an undeclared new operation is an increase of its own.
- **Separate keys are not separate people.** Key separation compares key ids. In this
  single-author project the baseline key, the manifest keys, and every approver key used so far
  were generated and held by the same author or by a CI job. The acceptance note says so.
- Budget and spend changes are deliberately not capability increases; they have their own
  signed controls. A raised budget needs no approval under this ADR.
- An approval binds a manifest's capability surface including its validity window, so renewing
  a manifest's window needs a new approval — and a new shadow run of the renewed twin.
