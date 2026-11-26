# Incident runbook

What each incident class looks like in the artifacts, and the operator response. Written
against the real event vocabulary — every "look for" below names an artifact or reason code
the harness actually emits. Every incident response ends the same way: preserve the evidence
first, then act. Nothing here authorizes deleting or rewriting a ledger.

Every command below was run in the Phase 5 drill (`docs/phase5/drill-acceptance.md`), and the
steps the drill found wrong or unfollowable were corrected in place. To rehearse a class without
a real incident, `scripts/incident_drill.py` writes one into a *copy* of a bundle.

## 1. Evidence-integrity incident

**What it looks like.** `summary.json` carries `evidence_integrity_incident: true`; the bundle
contains `integrity-incident.json` ("do not accept this run"); `verify-bundle` fails with
`explicit evidence-integrity incident`, a broken hash chain (`LedgerError`), an artifact digest
mismatch, or `artifact inventory differs from directory`.

**Response.**
1. Do not accept any finding from the run; the summary itself says so.
2. Preserve the bundle directory exactly as found (copy, do not re-run in place).
3. Run `purpleloop verify-ledger <bundle>/evidence.jsonl` to confirm the chain is broken (it
   answers only valid or invalid), then `purpleloop locate-ledger-break
   <bundle>/evidence.jsonl` to name the first broken line and why.
4. If the bundle was attested, run `purpleloop verify-attestation <bundle>`. The attestation
   signs the bundle's **inventory**, not the files themselves, so read the two results together:
   - attestation valid, `verify-bundle` says the inventory differs from the directory: the
     sealed inventory is authentic and files changed **after** sealing (tampering or
     corruption of the copy you hold);
   - attestation valid, inventory matches, ledger broken: the damage **predates** sealing;
   - attestation invalid: the inventory or the attestation itself was altered.
5. Re-run the scenario from the same seed (`purpleloop agent-run <scenario.yaml> <dir> --seed
   <seed>` for the agent lane, `purpleloop supportlab-run` for supportlab; `agent-run` writes the
   bundle under `<dir>/<scenario-id>/`). Compare `oracle_hash` in the two `summary.json` files:
   it is the semantic replay identity and is stable across commits. `event_replay_hash` and
   `manifest_digest` match only at the **same code commit** (the system prompt hash, for
   example, is signed into the manifest). A clean re-run plus a broken original indicates
   storage/transfer corruption; a re-run that reproduces the incident indicates a harness
   defect — file it and pin it with a test.

## 2. Suspected out-of-scope action

**What it looks like.** The `scope-bypass` gate blocks (`SCOPE_BYPASS`, naming the run id and
that run's ledger sequence number, e.g. `agent-approval-spoofing seq 106`); or a `RESULT` event
with decision `permit` whose action digest has no prior `POLICY` permit **in the same run's
ledger**; or a policy denial with a later execution for the same digest in that ledger. A permit
in another run of the suite is not a permit for this one.

An execution appended to a ledger after its run was sealed is not this class: `verify-bundle`
reports `normalized event hash mismatch`, which is an evidence-integrity incident (section 1).

**Response.**
1. Treat it as release-blocking (it is a Phase 0 release-blocking invariant).
2. Extract the decision record: `purpleloop audit-export <bundle> out.json` lists every
   admission/policy/budget decision per run with sequence numbers. It lists decisions only, not
   `RESULT` events, so for a permit-less execution what it shows is the **absence** of a permit
   for the digest in that run; the execution itself is the gate-named line of
   `<bundle>/<run>/evidence.jsonl`.
3. Identify the action digest (the `action_digest` of that line) and run `purpleloop
   locate-action <bundle>/<run> <digest>`. `plan.json` holds actions, not digests, and fixture
   control-plane calls and model intents compiled mid-run are not plan nodes; the command checks
   both and lists every event that names the digest. A digest that is neither a plan node nor a
   compiled intent is an execution the plan never authorized.
4. Reproduce under the same seed. The kernel is deterministic: a genuine bypass reproduces.
5. If reproduced, the fix lands with a property test in the authorization suite and, if the
   ledger invariant itself had a gap, a new case in `tests/phase4/test_gates.py`.

## 3. Budget breach

**What it looks like.** *Correct* behaviour is a `BUDGET` event with decision `deny`
(`BUDGET_EXCEEDED`, `WALL_TIME_EXCEEDED`) and a run that stopped fail-closed — that is a
budget outcome, not an incident. The incident forms are: the `budget-failure` gate blocking
(`BUDGET_VIOLATION`: charged use above signed limits, or execution after a budget denial in the
same run's ledger), or a nightly `budget-stop` recurring night after night (the nightly lane's
`artifacts/nightly/nightly.json`, and the tracking issue it files).

**Response.**
1. For a gate block: the ledger arithmetic or enforcement failed; treat as class 2 severity,
   reproduce from seed, fix with a test. For the arithmetic form, compare the run's
   `summary.json` `budget_used` with the re-run's. A re-run within limits means the stored
   summary, not the kernel, is wrong: `verify-bundle` does not cross-check `budget_used` against
   the ledger, and only an attestation binds the summary's content, so an unattested bundle's
   summary is evidence of what was written, not proof of what was charged.
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
   The container suites tear their project down in a `finally`, so after a failing suite there
   is nothing left to inspect: bring the same compose file up by hand under a throwaway project
   name and capture it there, e.g.
   `docker compose -f compose.phase2.yaml -p purpleloop-drill up --build --wait`, then
   `docker compose -f compose.phase2.yaml -p purpleloop-drill ps`, `docker network inspect
   purpleloop-drill_supportlab-isolated --format '{{.Internal}}'`, and the egress probe the
   suite runs, before `docker compose ... down --volumes`. The file needs
   `SUPPORTLAB_DATABASE_PASSWORD`, `SUPPORTLAB_CONTROL_CREDENTIAL`, and
   `SUPPORTLAB_ACTOR_CREDENTIALS` set; use fresh throwaway values.
3. Diff the compose files against the committed contract tests — those tests are the
   specification. For the Phase 1 fixture that is `tests/unit/test_compose_contract.py`; for
   supportlab (`compose.phase2.yaml`) it is
   `tests/phase2/test_supportlab_isolation.py::test_compose_isolation_contract`, and the unit
   contract test does **not** cover it (in the drill it passed against a weakened
   `compose.phase2.yaml`).
4. A genuine escape is a release-blocking finding against the harness itself; record it in the
   phase acceptance record like any other defect found by a failing command.

## 5. Nightly endpoint errors

**What it looks like.** `outcome.json` with `endpoint-error` (`MODEL_PROVIDER_UNAVAILABLE`,
DNS/TLS failures, `EVERY_REPETITION_EXCLUDED` on the stochastic lane). On the Phase 5 nightly
lane the same outcome appears in `artifacts/nightly/nightly.json` and in the tracking issue
`Nightly lane: non-pass outcome`, which each failing night comments on.

**Response.**
1. This is not a scenario failure and must not be triaged as one; the classification exists
   to keep the two apart.
2. Check the provider's status and the pinned endpoint's DNS.
3. If the endpoint moved permanently, the fix is a signed manifest change (the endpoint is a
   signed model asset), not an environment-variable edit.
4. Repeated endpoint errors across nights with a healthy provider mean the pin or profile is
   wrong; re-run `make agent-stochastic` locally with the same pin to reproduce.

## 6. Runaway loop detected

**What it looks like.** `summary.json` has `status: error`, `reason: RUNAWAY_LOOP_DETECTED`. The
run's ledger holds a `POLICY` event, decision `deny`, reason `RUNAWAY_LOOP_DETECTED`, whose
`data` names the `check` (`repetition` or `no-progress`), the `limit` and `observed` count, the
`window_stage`, the `action_fingerprint`, the `state_digest` and the `action_state_hash`. A refused
or rejected step also carries `refused`. The final `TERMINATION` event has the same reason and
`teardown_complete: true`. In a shadow bundle the same detection is `RUNAWAY_LOOP_WOULD_TRIP`
(decision `would-deny`), counted in `shadow-report.json` `would_be_loops`, and stops nothing.

This is **correct behaviour**, the kernel's loop guard (ADR 0018) ending a run fail-closed, like
a budget outcome. The incident forms are: a target-plane `RESULT` `COMPLETED` *after* the
detection event in the same ledger (the latch failed: treat as class 2, out of scope), or
`teardown_complete: false` (treat as class 4, containment).

**Response.**
1. Preserve the bundle. A stopped run is still sealed and verifies like any other:
   `purpleloop verify-bundle <bundle>` and `purpleloop verify-ledger
   <bundle>/<run>/evidence.jsonl`.
2. `purpleloop audit-export <bundle> out.json`: the run's decision record lists the `policy` and
   `termination` entries with reason `RUNAWAY_LOOP_DETECTED` and their sequence numbers.
3. Find what looped: `purpleloop locate-action <bundle>/<run> <action_digest>` on the detection
   event's `action_digest`. Its `origins` name the source, e.g. "model intent compiled at
   sequence N" or a plan node. For a refused or rejected attempt the digest is the refused
   step's own digest (or the rejected name's fingerprint), so read the `TOOL_INTENT_REFUSED`,
   `TOOL_INTENT_REJECTED` or `PROPOSAL` events just before the detection instead.
4. Decide which it is. A model or attacker that loops is a **finding about that model** (record
   it, do not loosen the limits to make the run pass). A legitimate scenario that trips means
   the signed limits are too tight for it. Measure with `uv run python
   scripts/loop_guard_margins.py --repeat-limit N --no-progress-limit K` and re-sign the
   manifest (or matrix spec) with new limits. Never patch the kernel.
5. A latch failure (step "incident forms" above) reproduces from the same seed. Fix it with a
   case in `tests/phase5/test_runaway_loop.py`.
