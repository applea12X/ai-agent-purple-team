# Phase 4 as built — CI quality system and portfolio release

This is the as-built design note for Phase 4. The working plan with its rationale is
[planning/phase4-plan.md](../planning/phase4-plan.md); the measured record is
[docs/phase4-acceptance.md](phase4-acceptance.md). Where this note and the PRD disagree, the
PRD wins.

## What Phase 4 is

Phase 4 turns the project's checkpoint discipline into CI enforcement and builds the release
machinery, while wiring the lanes that make the model-facing numbers real. Its central rule:

> Phase 4 adds the project's first real-model lanes and its first enforcing CI gates
> simultaneously, and they must never meet. Gates read deterministic verdicts only. A real
> model can make a report worse; it can never make CI red — and a test proves it, per gate.

## Contracts (all additive; 1.0–1.3 documents keep byte-identical canonical bytes)

- **Manifest 1.4** (`schemas/authorization.py`, `schemas/phase4.py`): `Phase4Grants` with
  `attestation_key_ids` (which keys may attest runs under this engagement), `retention` (one
  signed rule per artifact kind; `docs/retention-policy.md` records the defaults), and
  `nightly_scope` (the scenario subset and repetition count authorized for unattended
  real-model runs — spend authority as signed data, not workflow YAML).
- **`RunAttestation` 1.0** (ADR 0012): in-toto-shaped statement over the bundle inventory
  digest, signed with the existing Ed25519/JCS machinery, living outside the sealed inventory,
  verified by `verify-bundle --attestation`. `key_provenance` distinguishes a provided
  per-environment key from an ephemeral one.
- **`StochasticRunOutcome`**: the nightly lane's closed vocabulary (`pass`, `fail`,
  `budget-stop`, `skip-no-credential`, `endpoint-error`), written as `outcome.json` by
  `agent-run` so a failure is surfaced as what it is.
- **`ReproductionRecord`**: the stochastic lane's replay number with a required gap reason
  below 1, written as `reproduction.json` whenever repetitions > 1.
- **`RiskClassMetrics` / `RiskClassBaseline` / `RiskClassComparison`**: the typed inputs and
  output of the pre-registered per-class regression test (`scoring/phase4.py`).
- **`RegressionRegistry`** (`scenarios/regression-registry.json`): every accepted finding
  class mapped to its pinning pytest node id; covered entries must name a real test
  (`tests/phase4/test_regression_registry.py` fails on a dangling reference), and coverage is
  computed from the file.
- **`SmokeSet`** (`scenarios/smoke.json`): the named PR-lane subset — 14 scenarios across all
  three lanes including a browser-surface member, each required to exist and be labelled.

## The gates (ADR 0013)

`reporting/gates.py` holds five pure decision functions — scope bypass (ledger invariant: no
executed result without a prior policy permit, none after a standing denial), critical
regression (registry-covered pinning tests must run and pass, parsed from the JUnit report),
schema drift (canonical digests of frozen reference documents against
`baselines/schema-digests.json`), budget failure (charged use within signed limits; no
execution after a budget denial), and per-risk-class regression (the pre-registered test in
`docs/evaluation-methodology.md` against `baselines/corpus-baseline.json`). `purpleloop gates`
wires CI to the same functions; `--inject <class>` feeds a loudly-labelled violating input
through the same function for the red-branch protocol. Gates read binding verdicts only, and a
gate with nothing to examine blocks.

## Lanes (`.github/workflows/phase4.yml`; earlier workflows untouched)

- **`pr-fast` (WP4.1)**: asserts no model credential is present, runs lint/type/full suite
  with a JUnit report, the cross-lane `smoke-demo` (wall time measured against the stated
  600-second target and reported), current corpus metrics, and the five gates; evidence
  uploaded on success and failure.
- **`nightly-stochastic` (WP4.2)**: schedule/dispatch only; credentials from repository
  secrets; a missing credential is a recorded skip; ≥5 repetitions with judge and adaptive
  attacker; the classified `outcome.json` is printed and the job fails on any non-pass. It
  supersedes `phase3.yml`'s stochastic job as the maintained nightly without editing that
  file.
- **`release` (WP4.3)**: tag/dispatch; runs `holdout-check` (17 near-miss mutations, all
  denied, digest-pinned, held out of every tuning path by a grep test), the full agent demo,
  attestation (CI key from secrets, else ephemeral and recorded as such), verification, and
  the audit export.

## Release machinery (WP4.3)

`reporting/attestation.py`, `reporting/audit_export.py`, `control/holdout.py`,
`scenarios/holdout/mutations.json`, `docs/retention-policy.md`, `docs/incident-runbook.md`.
The audit export is one self-contained redacted JSON per bundle: per-run status, findings,
every admission/policy/budget decision with reason codes, embedded manifests and keys, the
attestation, and digest-verification instructions.

## Defect fixed during acceptance: attacker probes decided binding verdicts

Running `agent-demo` on the new compose fixture surfaced a regression on
`agent-indirect-markdown` that reproduced identically in process and at the Phase 3 commit, so it
was pre-existing rather than a container difference. The runner executed the bounded attacker's
proposals before the scored snapshot, letting an advisory component's writes decide binding
security verdicts and side-effect counts. The probes now run after every binding measurement of
the leg (`runtime/runner.py`), marked by an `ADVISORY_PROBES_AFTER_BINDING` lifecycle event. See
the ADR 0009 amendment, the correction note in `docs/phase3-acceptance.md`, and
`tests/phase4/test_attacker_isolation.py`, which fails against the Phase 3 runner.

## WP4.0 debt status

Implemented here: the `agent-demo`/`agent-run` `--fixture compose` path (4.0.7), outcome
classification and reproduction reporting (4.0.5's machinery), and the calibration/pin
plumbing was already in place from Phase 3. **Not yet run**: everything requiring a real model
endpoint — the stochastic lane against a real pin (4.0.1), real-pin token calibration (4.0.2),
a real API cost (4.0.3), real-judge agreement and the self-family delta (4.0.4), measured
stochastic variance (4.0.5's numbers), and the compromised-model property against a real model
(4.0.6). The acceptance record lists these as open, per the project rule that a number not
produced by a command actually run does not appear.

## Reviewer path (WP4.5)

`docs/reviewer-walkthrough.md` is the timed protocol; `docs/samples/` holds the three fixed
artifact sets (a passing attested bundle, an admission-denied run, and a deliberately
corrupted bundle labelled as such). The checkpoint is measured with an actual reviewer or
recorded as untested.
