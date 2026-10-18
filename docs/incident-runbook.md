# Incident runbook

What each incident class looks like in the artifacts, and the operator response. Written
against the real event vocabulary — every "look for" below names an artifact or reason code
the harness actually emits. Every incident response ends the same way: preserve the evidence
first, then act. Nothing here authorizes deleting or rewriting a ledger.

## 1. Evidence-integrity incident

**What it looks like.** `summary.json` carries `evidence_integrity_incident: true`; the bundle
contains `integrity-incident.json` ("do not accept this run"); `verify-bundle` fails with
`explicit evidence-integrity incident`, a broken hash chain (`LedgerError`), an artifact digest
mismatch, or `artifact inventory differs from directory`.

**Response.**
1. Do not accept any finding from the run; the summary itself says so.
2. Preserve the bundle directory exactly as found (copy, do not re-run in place).
3. Run `purpleloop verify-ledger <bundle>/evidence.jsonl` to localize the first broken event.
4. If the bundle was attested, run `purpleloop verify-attestation <bundle>`: a valid
   attestation over a broken bundle means the damage predates sealing; an invalid one means
   post-seal tampering or corruption.
5. Re-run the scenario from the same seed. The deterministic lanes replay bit-exactly, so a
   clean re-run plus a broken original indicates storage/transfer corruption; a re-run that
   reproduces the incident indicates a harness defect — file it and pin it with a test.

## 2. Suspected out-of-scope action

**What it looks like.** The `scope-bypass` gate blocks (`SCOPE_BYPASS` with the offending
sequence numbers); or a `RESULT` event with decision `permit` whose action digest has no prior
`POLICY` permit in the ledger; or a policy denial with a later execution for the same digest.

**Response.**
1. Treat it as release-blocking (it is a Phase 0 release-blocking invariant).
2. Extract the decision record: `purpleloop audit-export <bundle> out.json` lists every
   admission/policy/budget decision per run with sequence numbers.
3. Identify the action digest and find its compiled action in `plan.json`.
4. Reproduce under the same seed. The kernel is deterministic: a genuine bypass reproduces.
5. If reproduced, the fix lands with a property test in the authorization suite and, if the
   ledger invariant itself had a gap, a new case in `tests/phase4/test_gates.py`.

## 3. Budget breach

**What it looks like.** *Correct* behaviour is a `BUDGET` event with decision `deny`
(`BUDGET_EXCEEDED`, `WALL_TIME_EXCEEDED`) and a run that stopped fail-closed — that is a
budget outcome, not an incident. The incident forms are: the `budget-failure` gate blocking
(`BUDGET_VIOLATION`: charged use above signed limits, or execution after a budget denial), or
a nightly `outcome.json` of `budget-stop` recurring night after night.

**Response.**
1. For a gate block: the ledger arithmetic or enforcement failed; treat as class 2 severity,
   reproduce from seed, fix with a test.
2. For recurring nightly budget stops: the estimate or the signed cap is miscalibrated. Do not
   raise the cap in the workflow; the nightly cap is signed manifest data (`nightly_scope`),
   so the change is a reviewed manifest change, and the estimate-versus-actual delta in the
   run summary says which side is wrong.

## 4. Containment failure

**What it looks like.** The container-lane suites fail: egress unexpectedly succeeds, the
fixture root is writable, a process runs as root, or a control-plane call succeeds with a
customer credential. On the model plane: a `MODEL_ENDPOINT_RESOLVES_TO_TARGET` denial firing
in a lane where it never should, or its *absence* where a rebind was attempted.

**Response.**
1. Stop running evaluations until resolved; the containment posture is the project's strongest
   measured control.
2. Capture `docker compose ps`/`inspect` output for the affected project before teardown.
3. Diff the compose files against the committed contract tests
   (`tests/unit/test_compose_contract.py` and the isolation suites) — those tests are the
   specification.
4. A genuine escape is a release-blocking finding against the harness itself; record it in the
   phase acceptance record like any other defect found by a failing command.

## 5. Nightly endpoint errors

**What it looks like.** `outcome.json` with `endpoint-error` (`MODEL_PROVIDER_UNAVAILABLE`,
DNS/TLS failures, `EVERY_REPETITION_EXCLUDED` on the stochastic lane).

**Response.**
1. This is not a scenario failure and must not be triaged as one; the classification exists
   to keep the two apart.
2. Check the provider's status and the pinned endpoint's DNS.
3. If the endpoint moved permanently, the fix is a signed manifest change (the endpoint is a
   signed model asset), not an environment-variable edit.
4. Repeated endpoint errors across nights with a healthy provider mean the pin or profile is
   wrong; re-run `make agent-stochastic` locally with the same pin to reproduce.
