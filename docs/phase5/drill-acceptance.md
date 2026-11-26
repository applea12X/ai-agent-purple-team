# Incident runbook and retention drill — acceptance record

Date: November 25, 2026. Closes loose end **4.12** (`docs/phase5/loose-ends.md`): the retention
policy and the incident runbook had never been exercised.

**Method.** This was a tabletop drill backed by real commands. For each of the four runbook
incident classes named in the work order, an incident was produced from existing fault-injection
machinery or from a committed sample. `docs/incident-runbook.md` was then followed step by step,
as written, with the commands it names. Every place where the runbook was wrong, unclear, or
could not be followed is listed below with what was changed. Retention was resolved over a real
suite with a new dry-run command.

Every incident was made in a **copy** under the session scratchpad, never in the repository.
The scratch paths are shortened here to `$D`. Two kinds of bundle were used. `$D/smoke/<ts>` is
a real 14-run smoke suite produced by `uv run purpleloop smoke-demo --output-dir $D/smoke`
("wall time 14.054s against the stated 600s target", "Verified smoke bundle"). The other is the
committed sample `docs/samples/incident`.

The gate runs below pass `--junit $D/junit-gates.xml` (from `uv run pytest tests/phase4/test_gates.py
--junitxml=...`, 28 passed) and `--risk-current $D/corpus-current.json` (from `uv run purpleloop
corpus-baseline --output ...`, "classes=13 scenarios=25 failed=none"). That JUnit file holds only
the gate tests, so `critical-regression` blocks with `REGISTRY_TEST_NOT_RUN` in every gate run
here. That block is expected and is not part of the drill. The lines quoted are the two gates the
drill exercised.

## 1. Evidence-integrity incident

**Produced from:** `docs/samples/incident`, the committed sample in which one byte of event 3 was
altered after sealing. It was copied to `$D/incident-copy` (runbook step 2, "copy, do not re-run
in place").

| Step | Command | Result |
| --- | --- | --- |
| look for | `summary.json` / `integrity-incident.json` | `evidence_integrity_incident: false`, no `integrity-incident.json`. The damage was done after the run, so the run never flagged itself. |
| look for | `uv run purpleloop verify-bundle $D/incident-copy` | `INVALID: artifact inventory differs from directory`, exit 1 |
| 3 | `uv run purpleloop verify-ledger $D/incident-copy/evidence.jsonl` | `INVALID LEDGER_INVALID`, exit 1. **Nothing is localized.** |
| 3 (new) | `uv run purpleloop locate-ledger-break $D/incident-copy/evidence.jsonl` | `{"line": 4, "reason": "line is not a valid event", "valid": false}`. Line 4 is event 3, as the sample's README says. |
| 4 | `uv run purpleloop verify-attestation $D/incident-copy` | `VALID run-bundle 39aa5328… key=ephemeral-local (ephemeral)`, exit 0 |
| 5 | `uv run purpleloop agent-run scenarios/agent/agent-indirect-ticket.yaml $D/incident-rerun --seed 42` | `PASSED n=1 …`. Bundle at `$D/incident-rerun/agent-indirect-ticket/`; `verify-bundle` on it: `VALID … artifacts: 15, events: 102` |
| 5 | compare the two `summary.json` | `oracle_hash` equal (`0d5fd30d1a48…`), `status` equal, `scenario_digest` equal. `event_replay_hash` and `manifest_digest` **differ**. |

**Conclusion reached by following the runbook:** a clean re-run plus a broken original means
storage or transfer corruption of the copy, not a harness defect. That is the right conclusion
for a sample deliberately corrupted after sealing.

**Where the runbook was wrong or unclear (fixed in `docs/incident-runbook.md`):**

1. *Step 3 said `verify-ledger` "localizes the first broken event". It does not:* it prints
   `INVALID LEDGER_INVALID` only. There is now `purpleloop locate-ledger-break`
   (`src/purpleloop/reporting/incident_tools.py`), and step 3 names it.
2. *Step 4's inference was backwards for this case.* It said a valid attestation over a broken
   bundle means the damage predates sealing. The attestation signs the bundle's
   **inventory** (`reporting/attestation.py`: "attested subject does not match the bundle
   inventory"), not the files. So damage done after sealing leaves the attestation valid and
   breaks the inventory match, which is exactly what this sample shows. Step 4 now reads the
   attestation and `verify-bundle` results together, as three cases.
3. *Step 5 said the deterministic lanes "replay bit-exactly".* Across commits they do not. The
   sample was sealed at `672bda2`, before `b7fe527` changed the system prompt hash that is signed
   into the manifest, so `event_replay_hash` and `manifest_digest` differ while `oracle_hash`
   matches. Step 5 now says to compare `oracle_hash`, and to compare the other two only at the
   same commit. It also names the re-run command and `agent-run`'s `<dir>/<scenario-id>/`
   output layout. The first attempt here read `$D/incident-rerun/summary.json`, which does not
   exist.

## 2. Suspected out-of-scope action

**Produced from:** the `gates --inject scope-bypass` fault (`phase4_cli._injected_bypass_event`),
written into a copy of the real smoke suite by the new `scripts/incident_drill.py`. The
in-memory injection leaves no bundle for the runbook's commands to examine. The script appends
a `RESULT` permit for a digest that nothing in the run permitted. It appends through
`EvidenceLedger`, so the hash chain and anchor stay valid, then rebinds the summary's replay
hash and reseals the inventories: the record an honest kernel would leave after a genuine
bypass. The bundle still verifies (`verify-bundle`: `VALID … scenarios: 14`).

| Step | Command | Result |
| --- | --- | --- |
| produce | `uv run python scripts/incident_drill.py scope-bypass $D/scope-bypass` | `appended RESULT permit seq=106 digest=ffffffffffff... in …/agent-approval-spoofing` |
| look for | `uv run purpleloop gates $D/scope-bypass --junit … --risk-current …` | `BLOCKED scope-bypass: SCOPE_BYPASS — agent-approval-spoofing seq 106: executed without a policy permit` (after the fix below; before it, the detail was `seq 106` with no run named) |
| 2 | `uv run purpleloop audit-export $D/scope-bypass $D/scope-bypass-audit.json` | `EXPORTED runs=14`. The forged digest appears **nowhere** in the export: `decisions` lists admission, policy, budget, defense, and termination events, never the `RESULT`. |
| 3 | look up the digest in `plan.json` | 0 matches. `plan.json` stores actions, not digests, so **no** digest can be found there by search. |
| 3 (new) | `uv run purpleloop locate-action $D/scope-bypass/agent-approval-spoofing ffff…ffff` | origins: `neither a plan node nor a compiled model intent; no staged ledger event names it`; events: the one `result`/`permit` at sequence 106 |
| 4 | reproduce: `uv run purpleloop smoke-demo --output-dir $D/smoke-rerun` | `Verified smoke bundle`. The `scope-bypass` gate passes on the re-run, so the bypass does not reproduce. That is correct, since it was injected. A genuine one would reproduce. |

**First attempt, and a finding.** Before the summary's replay hash was rebound, `verify-bundle`
on the bundle with the appended event said `INVALID: normalized event hash mismatch`. An event
appended after a run is sealed is caught as an integrity incident before any gate sees it. That
is the right behaviour, and the runbook now says so.

**A defect in the Phase 4 scope gate, found here and fixed.** A suite bundle's events are whole
ledgers concatenated (`_bundle_events`). `scope_gate` and `budget_gate` matched permits and
denials by action digest *across runs*. In the real smoke suite, **37 of the 100** executed
action digests are shared across runs: the fixture control-plane calls are identical in every
run. The drill's `cross-run-bypass` mode appends to the last run (`ssrf-link-preview`) a
`RESULT` permit for a digest that only *another* run permitted:

| Bundle | `scope-bypass` gate before the fix | after the fix |
| --- | --- | --- |
| `$D/smoke/<ts>` (clean) | `pass NO_BYPASS_OBSERVED — 302 executed results` | `pass NO_BYPASS_OBSERVED — 302 executed results` |
| `$D/cross-run` (`incident_drill.py cross-run-bypass`) | `pass NO_BYPASS_OBSERVED — 303 executed results` (**missed**) | `BLOCKED SCOPE_BYPASS — ssrf-link-preview seq 78: executed without a policy permit` |
| `$D/scope-bypass` | `BLOCKED … seq 106` | `BLOCKED … agent-approval-spoofing seq 106` |
| `gates --inject scope-bypass --inject budget-failure` on the clean suite | both `BLOCKED` | both `BLOCKED` (`gate-proof seq 78`, `gate-proof: requests charged 601 …`) |

Root cause: the guard history was keyed by digest alone. Fix: `reporting/gates.ledger_segments`
splits the stream wherever a sequence number stops increasing. That point is a new ledger,
because every verified ledger starts at 0 and strictly increases. Both gates now key their
history by (ledger, digest), and violation details name the run id. Pinned by
`tests/phase5/test_gate_ledger_segments.py`. On the old `gates.py` in a scratch copy,
`test_a_real_run_cannot_borrow_another_runs_permit` (the missed bypass) and
`test_a_budget_denial_in_another_run_does_not_flag_this_runs_execution` (the mirror false
positive) both fail, on assertions; the other two pass on both. The phase 4 and phase 5 gate
suites still pass (`uv run pytest tests/phase4 tests/phase5/test_phase5_gate_isolation.py`). The
WP5.0.7 record quotes the old detail text, `seq 78: executed without a policy permit`. That
text is historical, and the record was left as written.

**Where the runbook was wrong or unclear (fixed):** "with the offending sequence numbers" did not
say *which run's* sequence numbers, and in a suite they were ambiguous. Step 2 implied the
export shows the execution, but it shows only the missing permit. Step 3 could not be followed
at all: `plan.json` has no digests, and control-plane calls and compiled intents are not plan
nodes. It now uses `locate-action`.

## 3. Budget breach

**Produced from:** the `gates --inject budget-failure` fault, materialized by
`uv run python scripts/incident_drill.py budget-breach $D/budget-breach`. That command reported
`set budget_used.requests=601 over the signed limit 600 in …/agent-approval-spoofing`, and the
inventories were resealed. `verify-bundle`: `VALID … scenarios: 14`.

| Step | Command | Result |
| --- | --- | --- |
| look for | `uv run purpleloop gates $D/budget-breach …` | `BLOCKED budget-failure: BUDGET_VIOLATION — agent-approval-spoofing: requests charged 601 over signed limit 600` |
| 1 | reproduce from seed (`$D/smoke-rerun`, above) and compare `budget_used.requests` | breach copy **601**, re-run **25**, original **25**. `oracle_hash` equal between re-run and original. |

**Conclusion reached:** the kernel did not over-charge. The stored summary is wrong, which here
is an edit, so this is handled as evidence integrity, not as an enforcement defect.

**Where the runbook was unclear (fixed):** it did not say what "reproduce from seed" compares
for the arithmetic form. More importantly, it did not say that `verify-bundle` does not
cross-check `budget_used` against the ledger. An unattested bundle whose summary was edited and
whose inventory was resealed still verifies. Only an attestation binds the summary's content.
This is the documented "tamper-evident, local anchor" limit (row 0.2, ADR 0003), now stated
where the operator needs it. The runbook also pointed at a nightly `outcome.json`; the Phase 5
nightly lane writes `nightly.json` and files a tracking issue, and the runbook now names both.

## 4. Containment failure

**Produced from:** the containment suite itself, against a deliberately weakened compose file.
In a scratch copy of the tree at `8f000e0`, `compose.phase2.yaml`'s `supportlab-isolated`
network was changed from `internal: true` to `internal: false`. Docker 29.7.2.

| Step | Command | Result |
| --- | --- | --- |
| look for | `PURPLELOOP_CONTAINER_TESTS=1 uv run pytest tests/phase2/test_supportlab_isolation.py` (scratch copy) | `2 failed, 5 passed in 36.51s`. `test_container_isolation_and_cross_plane_credentials`: `AssertionError: external egress`; `test_compose_isolation_contract`: `assert False` |
| 1 | stop evaluations | done; nothing else ran on the container lane until the file was restored |
| 2 | `docker compose ls -a`, `docker ps -a` | **nothing left to capture.** The suite's `ComposeSupportlab.close()` ran `down --volumes` in its `finally`. |
| 2 (revised) | `docker compose -f compose.phase2.yaml -p purpleloop-drill up --build --wait --wait-timeout 60` (throwaway credentials) | exit 0. `ps`: db, fixture, ingress, upstream all `running` |
| 2 (revised) | `docker network inspect purpleloop-drill_supportlab-isolated --format 'internal={{.Internal}}'` | `internal=false` |
| 2 (revised) | the suite's egress probe, by `docker compose … exec -T supportlab-fixture` (a TCP connect to 1.1.1.1:443) | `EGRESS SUCCEEDED` |
| 2 (revised) | `docker compose … down --volumes --timeout 0` | exit 0 |
| 3 | `uv run pytest tests/unit/test_compose_contract.py` (scratch copy, weakened file) | **`1 passed`**. The contract test the runbook named does not cover `compose.phase2.yaml`. |
| fix | restore the committed `compose.phase2.yaml`; re-run the container suite | `7 passed in 9.63s` |

**Where the runbook was wrong (fixed):** step 2 ("capture … before teardown") cannot be done
after a failing suite, because the suite tears the project down itself. The runbook now gives
the by-hand bring-up under a throwaway project name, and the three environment variables the
compose file requires. Step 3 named `tests/unit/test_compose_contract.py` as the specification,
which did not catch this weakening. It now names the supportlab contract test, which did.

## Retention resolution on a real suite

`purpleloop retention-plan <root>` (`src/purpleloop/reporting/retention.py`) is new. It verifies
the signed nightly manifest, reads its `Phase4Grants.retention`, and resolves every file under
the root. It reports each file's kind, its age taken from the run's first ledger timestamp, its
deletion date, and any hold. It **never deletes**, and a test asserts that the tree is
unchanged. The signed rules are raw-ledgers 0 (repo life), attestations 0, bundles 90 days,
browser-artifacts 90 days, model-transcripts 30 days.

Over the real smoke suite `$D/smoke/<ts>` (14 runs, 233 files, first ledger events of
2026-11-25):

| Command | Result |
| --- | --- |
| `retention-plan $D/smoke/<ts> --as-of 2026-11-25` | `files=233 due=0` |
| `… --as-of 2026-12-26` | `files=233 due=0` |
| `… --as-of 2027-02-24` (first run, before the suite fix below) | `files=233 due=5`: the 5 suite-level files (`inventory.json`, `report.*`, `suite.json`) |
| `… --as-of 2027-02-24` (after the suite fix) | `files=233 due=0`; bundles 187 files held, browser-artifacts 4 held, model-transcripts 14 held, raw-ledgers 28 never due |

The deletion dates, if no hold applied, are: model-transcripts (Inspect logs) 2026-12-25;
bundles and browser artifacts 2027-02-23; ledgers never. Every file of every run was held by
`1 finding(s): no closure record exists, so held as open`. Over the committed samples,
`retention-plan docs/samples --as-of 2100-01-01` gave `files=43 due=4`. The 4 due files are the
`denied-run` sample's files: it has no summary and no attestation, so nothing holds it. The
attested samples are held by their attestations.

**Where the policy was wrong or unclear (fixed in `docs/retention-policy.md`):**

1. **Suite files fell due while every run they describe was held.** The first resolution aged
   suite-level files by mtime and gave them no holds. Deleting the suite `inventory.json` would
   have broken `verify-bundle` on a suite whose runs were all kept. Suite files now take the age
   of their oldest run and inherit the holds of the runs they cover. Pinned by
   `test_suite_level_files_inherit_the_age_and_holds_of_the_runs_they_cover`.
2. **`bundles` had two durations for one signed rule.** The policy said 0 for release bundles
   and 90 days for CI bundles, but the schema allows one rule per kind. The signed rule is now
   90 days, and a release bundle is kept because its attestation holds it.
3. **Model transcripts live in the ledger too.** In the re-run agent bundle, 6 `RESULT` events
   carry the model's reply and the retrieved chunk bodies (redacted). The ledger is
   `raw-ledgers`, kept for the life of the repository, and that text cannot be removed without
   breaking the chain. So the 30-day `model-transcripts` rule can only delete the Inspect logs,
   a second copy. The policy now says so. Changing what the ledger records is a design decision
   for the author and was not made here.
4. **"Open finding" has no record behind it.** No finding-closure record exists, so the
   resolver treats every finding as open. In practice nothing in an evaluation suite is ever
   due. That is the conservative reading, and the policy now states it.

## Tests that pin this

`tests/phase5/test_incident_drill.py` covers `locate-ledger-break` on the real incident sample,
a well-formed but edited event, an anchor mismatch, `locate-action`'s three origins over the
real passing sample, the drill script's two bypass modes against `scope_gate`, and the script's
refusal to touch the repository. `tests/phase5/test_gate_ledger_segments.py` covers the gate
fix. `tests/phase5/test_retention_plan.py` covers the signed rules, kinds, ledger-based age,
holds, suite inheritance, and the dry-run guarantee.

## What this does not show

- No real incident occurred. Every incident was injected, and a drill shows only that the
  runbook can be followed for the injected forms.
- Section 5 of the runbook (nightly endpoint errors) was not drilled. It needs a networked
  endpoint, which this drill had no access to and did not call.
- The containment drill weakened one control (network `internal`). The others the suite checks
  (read-only root, non-root user, cross-plane credentials) were not individually weakened.
- `retention-plan` resolves rules and deletes nothing. No deletion tooling exists or was built,
  so the retention policy is still enforced by nobody. What exists is a plan an operator can
  review.
- The tabletop steps ("treat as release-blocking", "stop running evaluations") are judgement
  steps. The drill records that they were taken, not that they were tested.
