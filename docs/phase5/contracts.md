# Phase 5 contracts — as built

Plan §3. This note lists every new or bumped contract, where it lives, and the rules it enforces.
It covers types, canonical bytes, signing, and validation only. The behavior that uses these
types (shadow execution, approval enforcement at admission, the matrix runner, telemetry, the
review UI, the codelab fixture, importers) belongs to WP5.1–WP5.6, and each of those packages
writes its own acceptance note.

## Contracts and versions

`uv run purpleloop phase5-contracts` prints this table from `schemas.phase5.CONTRACT_VERSIONS`.

| Contract | Version | Type | Module |
| --- | --- | --- | --- |
| Authorization manifest | 1.5.0 | `AuthorizationManifest` + `Phase5Grants` | `schemas/authorization.py`, `schemas/phase5.py` |
| Scenario | 1.4.0 | `Phase1Scenario` + `ImportSource` | `schemas/phase1.py`, `schemas/phase5.py` |
| Risk approval | 1.0.0 | `RiskApproval` (signed) | `schemas/phase5.py` |
| Shadow report | 1.0.0 | `ShadowReport` (sealed bundle member) | `schemas/phase5.py` |
| Evaluation matrix | 1.0.0 | `EvaluationMatrix` + `MatrixRow` (signed) | `schemas/phase5.py` |
| Matrix cell | 1.0.0 | `MatrixCell` (non-binding) | `schemas/phase5.py` |
| Defense dependence | 1.0.0 | `DefenseDependence` (non-binding) | `schemas/phase5.py` |
| Adjudication record | 1.0.0 | `AdjudicationRecord` (signed, not a verdict) | `schemas/phase5.py` |

Supporting vocabularies in `schemas/phase5.py`: `ActionClass` (closed StrEnum, ordered by `.rank`:
`read < write < external-send < code-exec`; `ACTION_CLASS_ORDER`, `highest_action_class`),
`CapabilityIncrease` (closed StrEnum of the six plan kinds; `CAPABILITY_INCREASES`),
`ScenarioLane` / `SCENARIO_LANES` (adds `codelab`), `classify_dependence`.

## Rules each contract enforces

**Manifest 1.5.** Keeps every 1.1–1.4 rule (loopback assets, Phase 1–4 grants all required) and
requires `phase5`. `action_classes` is non-empty and must cover every permitted side effect
(`read` → `read`, `write` → `write`). `run_mode` defaults to `execute`. `risk_approvals` and
`matrix_scope` are SHA-256 digests. `telemetry`, when present, must name a signed asset.
`AuthorizationManifest.capability_surface_digest()` is the manifest digest with the
`risk_approvals` list emptied. An approval binds to it: the manifest names the approval, so the
approval cannot name the full manifest digest without a cycle.

**Scenario 1.4.** `origin` and `public_exposure` must be stated explicitly. `import_source`
(framework, upstream version or commit, license, case id) is required exactly when
`origin: imported`, and its license must match the scenario's. `lane` is optional and may be
`codelab`. None of these fields is allowed on 1.1–1.3. Agent steps are allowed on 1.3 and 1.4.
The Phase 4 `SmokeLane` vocabulary is frozen and was not widened.

**ShadowReport.** `adapter_calls` is typed as the literal `0`, so a shadow run that reached an
adapter cannot produce a report. `proposal_rejection_rate` must equal `rejected / total`, and
counts are positive and keyed by identifier. `report_digest()` is what an approval names.

**RiskApproval.** Binds engagement, `baseline_digest`, `manifest_surface_digest`, the exact
`capability_delta` (non-empty; `covers()` is set equality), `shadow_report_digest`, a forward
`issued_at`/`expires_at` window, and `approver_key_id`.

**EvaluationMatrix.** Each row has one distinct seed per repetition (≥ 5). Columns are unique and
include the baseline column. The delimitation-blind anchor row is mandatory, because the
dependence classification is defined by it. An anchor row runs on the offline provider; a
real-pin row does not. The `greedy`/`sampled` label must match the temperature. The contrast
family, McNemar exact test, and Holm correction are fixed literals, and `alpha` is in (0, 1).

**MatrixCell / DefenseDependence.** Provenance is `advisory` or `pinned-stochastic` by type; a
`deterministic` value does not validate. A cell's `value` must equal `successes / n` and lie
inside its interval. A classification must follow from the credited and uncredited rows, and
the delimitation-blind row must be among the evaluated rows.

**AdjudicationRecord.** Not a `Scored` value and has no `provenance` field. A true-positive or
false-positive label must cite at least one evidence id. `blinded` records whether the oracle
verdict was hidden while the label was chosen.

## Signing and verification — `control/phase5_signing.py`

Uses the same construction as ADR 0002 and ADR 0012: Ed25519 over the JCS canonical bytes with
`signature` excluded, base64-encoded. No new cryptography. A test checks the signature against
hand-built JCS bytes and against `sign_manifest`.

- `sign_record(record, private_key)` for any `SignedRecord` (`RiskApproval`, `EvaluationMatrix`,
  `AdjudicationRecord`).
- `verify_record_signature(record, public_keys)`.
- `verify_risk_approval(approval, public_keys, *, manifest, shadow_report=None, now=None)`.
  Checks run in this order: trusted key, signature, validity window, engagement, capability
  surface, key separation, then the shadow report digest and engagement when a report is given.
  It does not compute the delta. WP5.1 calls `approval.covers(capability_delta(...))`.
- `verify_matrix_spec(spec, public_keys, *, manifest=None)`. With a manifest, it also checks the
  engagement and that `phase5.matrix_scope` equals the spec digest.
- `verify_adjudication(record, public_keys, *, bundle_digest=None)`.
- `key_separation_violations(approver_key_id, manifest)` (pure) and
  `require_key_separation(...)`. The approver key id may be neither the manifest's `key_id` nor
  any of its `phase4.attestation_key_ids`.
- On failure: `SignedDocumentError.reason_code` ∈ `UNKNOWN_SIGNING_KEY`, `INVALID_SIGNATURE`,
  `APPROVAL_NOT_YET_VALID`, `APPROVAL_EXPIRED`, `APPROVAL_ENGAGEMENT_MISMATCH`,
  `APPROVAL_MANIFEST_MISMATCH`, `APPROVER_KEY_NOT_SEPARATE`, `APPROVAL_SHADOW_MISMATCH`,
  `MATRIX_ENGAGEMENT_MISMATCH`, `MATRIX_NOT_AUTHORIZED`, `ADJUDICATION_BUNDLE_MISMATCH`.

## Gate boundary and schema drift

`reporting/gates.py`: every public gate function now checks its inputs by runtime type before it
computes anything, and raises `GateInputError` (a subclass of `AdvisoryVerdictError`) on any
other type. Tests push `MatrixCell`, `DefenseDependence`, and `AdjudicationRecord` through every
typed input of every gate. Clean inputs still produce the same five decisions.

`baselines/schema-digests.json` gains eight references: `authorization-manifest-1.5`,
`scenario-1.4`, `shadow-report-1.0`, `risk-approval-1.0`, `evaluation-matrix-1.0`,
`matrix-cell-1.0`, `defense-dependence-1.0`, `adjudication-record-1.0`. They are built from
constants in `reporting/phase5_references.py`. The six Phase 4 digests are unchanged.

## Byte identity, as measured

These digests were recorded at `a79f185` before any Phase 5 code existed, and are pinned in
`tests/phase5/test_phase5_manifest.py` and `tests/phase5/test_phase5_scenario.py`:

- manifests 1.0, 1.1 (`demo_manifest`), 1.2 (`supportlab_manifest`), and 1.3
  (`supportlab_agent_manifest`), each built at a fixed instant;
- the 1.3 and 1.4 reference manifests;
- per-lane corpus digests for all 48 scenarios (phase1 5, supportlab 18, agent 25).

All are unchanged.

## What this does not do

- No lane admits a 1.5 manifest or a 1.4 scenario yet. `LaneContract.manifest_versions` and
  `scenario_versions` are unchanged (`1.1`/`1.2`/`1.3`). Widening them is the job of the work
  package that needs it (WP5.1, WP5.5, WP5.6).
- No `capability_delta`, no `SHADOW_SUPPRESSED` event kind, no admission check (WP5.1).
- Key separation compares key ids, not key material, and two key ids held by one author are
  still one author. Acceptance notes must say who held which key.
- `RiskApproval.covers` is exact set equality. Combining several approvals is WP5.1's decision.
