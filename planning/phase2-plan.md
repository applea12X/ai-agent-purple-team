# Phase 2 implementation plan — realistic SaaS and browser lane

**Status: implemented (2026-09-07).** This working plan is superseded by the as-built design note
[docs/phase2-plan.md](../docs/phase2-plan.md) and the measured record in
[docs/phase2-acceptance.md](../docs/phase2-acceptance.md). It is retained for its rationale. Section 8, Phase 2 of
[PRD.md](PRD.md) is authoritative; where this document and the PRD disagree, the PRD wins. On
completion this plan is superseded by an as-built design note (`docs/phase2-plan.md`, matching
the Phase 1 pattern) and a measured record in `docs/phase2-acceptance.md`.

---

## 0. Verified starting point

Commit `ecf1ada`. Measured in `docs/phase1-acceptance.md`: 133 tests passing with one
container-gated skip, 88.47% branch coverage, 100/100 deterministic replay trials, seeded recall
1.0, zero false positives across 20 defended negative controls.

### What exists and is reusable as-is

| Area | Module | Reuse in Phase 2 |
| --- | --- | --- |
| Per-action authority | `runtime/runtime.py` (`SafetyRuntime`) | Unchanged. Still the only path to I/O. |
| Lifecycle | `runtime/runner.py` (`PurpleTeamRunner`) | Extended with new stages, not replaced. |
| Control plane | `runtime/fixture.py` (`FixtureController`) | Generalized over fixtures. |
| Plan compilation | `control/plan_compiler.py` | Extended with typed browser nodes. |
| Tool contracts | `control/tools.py` (`ToolDefinition`, `ToolRegistry`) | Reused; tenancy resolution changes (§3.3). |
| Adapter dispatch | `adapters/phase1.py` (`AdapterRegistry`) | Reused; browser adapter registers into it. |
| HTTP driver | `adapters/phase1.py` (`HttpAdapter`, `ToolAdapter`) | Reused against `supportlab`. |
| Oracles / detectors | `scoring/phase1.py` | Operator set unchanged; new paths only. |
| Metrics | `scoring/phase1.py` (`corpus_metrics`) | Reused; corpus grows, metric does not change shape. |
| Evidence bundle | `reporting/bundle.py` | Extended with browser trace artifacts. |
| Canonicalization | `schemas/common.py` (`order_sets`) | Unchanged. Do not regress the JCS/set fix. |
| Ingress | `fixture/relay.py` | Reused, and finally tested (WP2.0). |

### What does not exist yet

`targets/supportlab/`, `policies/`, any PostgreSQL dependency, any Playwright dependency, any
browser adapter, and any scenario outside `scenarios/phase1/`. Section 5 of the PRD lists
`docs/prd.md` and `policies/`; neither is in the tree.

### Constraints inherited from Phase 1 that shape this phase

- `HttpAdapter.preflight` rejects any scheme other than `http`, deliberately, because the only
  registered target is a loopback fixture.
- `ChatResult.tool_intents` is capped at one intent. Sufficient for Phase 2; Phase 3 raises it.
- `control/phase1_tools.py::definition` binds resource ownership through a **hardcoded
  `resource_tenants` map** (`record-a → tenant-a`, and so on). This does not survive a persistent
  multi-org database and is the single largest contract change in this phase (§3.3).
- The fixture image build is not offline; base images resolve from public registries.

---

## 1. Objectives

1. Replace the single in-memory Phase 1 fixture with `supportlab`: a persistent, multi-org,
   multi-role SaaS application backed by PostgreSQL, with toggleable flaws that map one-to-one to
   registry defense profiles.
2. Add a browser surface through a direct Playwright adapter that is subject to exactly the same
   authorization, budget, cancellation, redaction, and evidence rules as the HTTP adapter.
3. Grow the corpus to 15–20 labelled scenarios spanning SaaS authorization and workflow threats,
   with cross-surface scenarios that let API and browser oracles be compared.
4. Do all of the above without weakening any Phase 1 invariant, and without touching the Phase 0
   or Phase 1 lanes.

### Non-goals for this phase

Real model calls, the RAG assistant and agent tools, adaptive attackers, LLM judges, third-party
attack imports, and token/cost budgeting. All of these are Phase 3. Phase 2 stays offline for
models: the chat adapter continues to be backed only by `OfflineModelStore`.

---

## 2. The two hard problems

Everything else in this phase is ordinary engineering. These two are where the phase fails if it
fails, so they get designed before any code is written.

### 2.1 Determinism under a real database

Phase 1's determinism came free from an in-memory dict with a seeded generator and a logical
clock. PostgreSQL breaks that in four specific ways, each with a required mitigation:

| Threat to determinism | Mitigation |
| --- | --- |
| Unordered result sets — Postgres may return rows in any order without `ORDER BY` | Every query that reaches scored output carries an explicit total ordering. Enforced by a test that greps the query layer, not by convention. |
| Sequence-generated IDs vary with insert order and retries | Deterministic identifiers derived from the seed, not `SERIAL`/`IDENTITY`. Sequences are reserved for rows that never reach scored output. |
| `now()`, `random()`, `gen_random_uuid()` inside the database | Forbidden in application queries and in seed data. The injected logical clock stays authoritative and is passed in as a parameter. |
| Snapshot content varies with physical layout | The snapshot hash is computed from a canonical ordered `SELECT` over the scored tables, serialized through the existing JCS path — **not** from `pg_dump`, whose output carries non-deterministic and version-dependent detail. |

**Reset strategy — recommendation: template database.** Seed once into a template, then
`DROP DATABASE`/`CREATE DATABASE ... TEMPLATE supportlab_seed` per leg. This gives byte-identical
starting state, is fast enough at fixture scale, and is verified rather than trusted: the runner
recomputes the snapshot hash after reset and refuses to start the paired leg unless it equals the
baseline hash, exactly as Phase 1 does today.

The rejected alternative is a wrapping transaction rolled back per leg. It is faster but it
changes the isolation the application runs under, which is itself part of what several workflow
scenarios exercise. Record this in an ADR.

### 2.2 Determinism under a browser

The browser is not bit-reproducible and no amount of care will make it so. The plan is therefore
to bound what determinism is claimed for, rather than to claim it and then quietly exclude
mismatches.

- Scored output derives **only** from application state and typed DOM assertions. Never from
  screenshot comparison, timing, or rendered pixels.
- Use Playwright's clock emulation to freeze time in the page, so client-side timestamps do not
  leak into the DOM assertions that oracles read.
- Fixed viewport, fixed locale, fixed timezone, animations disabled, downloads disabled, a fresh
  context per leg with no persisted storage state.
- Explicit waits on typed selectors only. No arbitrary sleeps anywhere in the adapter or in
  scenario steps.
- The browser lane reports **its own replay rate, separately**, with a stated reason for any gap.
  It is not averaged into the API lane's number.

---

## 3. Contract changes

Every change here is additive and versioned. Phase 0 and Phase 1 manifests, scenarios, ledgers,
and bundles must continue to load, verify, and produce identical digests.

### 3.1 Manifest 1.2

Adds: browser-capable assets (origin, allowed paths, allowed subresource origins); a database
credential scope that no attack credential can reference; per-run containment identity; and
resource-ownership scope (§3.3). Manifest 1.0 stays read-only. Manifest 1.1 keeps exactly its
current grants. New optional fields are omitted from legacy canonical serialization so Phase 0
and Phase 1 digests and signatures are bit-identical to today — this is a test, not an intention.

### 3.2 Scenario 1.2

Adds: a `surface` field (`api` | `browser` | `both`); typed browser steps; and, for cross-surface
scenarios, a shared oracle reference so both surfaces are scored by the same specification. Load
1.0 and 1.1 documents through the existing explicit conversion path. Do not invent missing fields.

### 3.3 Resource ownership — the tenancy contract change

Phase 1 binds a resource to a tenant through a literal map inside
`control/phase1_tools.py::definition`. With two organizations and a database of seeded rows, that
map cannot be enumerated in code, and the obvious fix — asking the fixture who owns a row — is
wrong, because the fixture is the untrusted component under test. A compromised or buggy fixture
could then authorize the harness against a row it should never touch.

**Approach:** ownership comes from the signed manifest, not from the application. The manifest
declares resource-ownership scope as signed ranges or explicit ID sets tied to the deterministic
seed, so the kernel resolves `resource → tenant` from signed data alone. The seed is
deterministic precisely so this is enumerable at signing time. The fixture's own opinion about
ownership is recorded as observed data and is exactly what the oracle evaluates — it never feeds
the authorization decision.

This preserves the Phase 1 invariant that matters most here: harness authorization and target
vulnerability are independent facts.

### 3.4 `ActionRequest` and the adapter registry

Add typed browser arguments (navigate / fill / click / read) resolved from signed asset IDs.
Register `browser` as a new adapter name with its operations. Registration stays immutable after
admission and duplicate keys still fail startup. Free-form JavaScript, arbitrary URLs, and
arbitrary selectors from planner output are rejected **at compile time**, not at execution time.

---

## 4. Work packages

### WP2.0 — Clear Phase 1 debt

Do this first. It is small, it is a prerequisite for trusting Phase 2's own numbers, and it gets
harder once the tree doubles in size.

| # | Task | Done when |
| --- | --- | --- |
| 2.0.1 | Host-side unit test for `fixture/relay.py` | Relay is covered in the deterministic lane, or the acceptance record states precisely why it cannot be and it stays excluded on purpose. |
| 2.0.2 | Pin every base image by digest; add a pre-pull / cached-image path | `make phase2-demo` cannot fail on registry DNS. |
| 2.0.3 | Classify image-build failure as an outcome distinct from evaluation failure | A build failure reports as such and is not counted in evaluation denominators. |
| 2.0.4 | Promote the `PYTHONHASHSEED` matrix to a standing CI job, ≥5 seeds | The JCS/`frozenset` class of defect cannot regress silently. |
| 2.0.5 | Reconcile PRD section 5 with the tree | `policies/` exists, or the path list is corrected. `docs/prd.md` resolves to `planning/PRD.md`. |

### WP2.1 — `supportlab`

Files: `targets/supportlab/` (Dockerfile, migrations, seed), `src/purpleloop/fixture/supportlab/`
(app, control plane, defense toggles), `compose.phase2.yaml`.

**Domain.** Two organizations; at least four users spanning customer, agent, and admin; tickets,
documents, refunds, exports, an audit log, and canary records. Every value synthetic.

**Data layer.** PostgreSQL with migrations and a deterministic seeded dataset. Seeding returns a
canonical state hash the runner verifies before each paired leg, exactly as Phase 1 does. All
four determinism mitigations from §2.1 apply.

**Control plane.** Same shape as Phase 1's — provision, seed, snapshot, telemetry, defense, reset,
teardown — separately scoped and unaddressable by attack credentials, driven through
`FixtureController` so control calls draw on the run's shared budget.

**Flaw toggles.** Each is a named configuration value whose vulnerable/defended pair is a registry
defense profile the signed manifest must pre-authorize:

1. Object-level authorization (BOLA) — cross-org object read.
2. Function-level authorization (BFLA) — customer reaching an admin operation.
3. Property-level — mass assignment onto a protected column.
4. Workflow — refund or export state transition without a verified approval record.
5. SSRF — an upstream fetch whose destination is attacker-influenced.
6. Unsafe upstream consumption — upstream response trusted into a privileged path.

**Containment.** Identical posture to Phase 1: read-only root, tmpfs state, non-root user, dropped
capabilities, `no-new-privileges`, internal-only network, loopback ingress relay, no egress.
PostgreSQL joins the internal network with no published ports and per-run synthetic credentials
generated by the harness. Attack credentials cannot address the database directly.

### WP2.2 — Browser adapter

Files: `src/purpleloop/adapters/browser.py`, browser contract tests, Playwright pinned in
`pyproject.toml`.

| # | Task | Notes |
| --- | --- | --- |
| 2.2.1 | Register a direct Playwright adapter in `AdapterRegistry` | It never selects its own target. Plans carry typed steps resolved from signed asset IDs. |
| 2.2.2 | Fresh context per leg | No shared profile or storage state; downloads disabled; fixed viewport, locale, timezone; animations off; clock frozen. |
| 2.2.3 | Route-level origin authorization | Every navigation, redirect, and subresource origin authorized *before* it happens. Unauthorized origins abort at the routing layer, record a policy denial, and charge the run budget. Never silently dropped. |
| 2.2.4 | Satisfy the shared adapter contract suite | Typed I/O, deadlines, cancellation, kill-switch cooperation, idempotency, redaction, bounded output, no hidden network fallback. |
| 2.2.5 | Teardown in the `finally` path | Browser processes killed even on failure, timeout, budget exhaustion, or cancellation. |
| 2.2.6 | Trace and screenshot artifacts | Per-leg trace ZIP and screenshots written to the run directory, redacted, referenced by digest in the inventory. |

The kill-switch requirement deserves attention: a Playwright browser is an out-of-process child,
so Phase 0's p99 measurement — which covered cooperative in-process cancellation — does not
transfer. Measure browser-lane emergency stop separately and report it as its own number.

### WP2.3 — Corpus, 15–20 scenarios

Coverage required: object-, function-, and property-level authorization; authentication and role
boundaries; sensitive workflows (refund, export approval); SSRF; misconfiguration and inventory;
unsafe upstream consumption; cross-role and cross-tenant workflows.

Every scenario keeps the Phase 1 shape — vulnerable seed, clean utility task, baseline attack,
positive control, clean or defended negative control, deterministic oracle, expected detector
behavior, one pre-approved defense — and every one is labelled in ground truth. An unlabelled
scenario continues to raise rather than be skipped. Where a workflow has both an API and a browser
path, author both against the same oracle so cross-surface agreement is measured, not asserted.

### WP2.4 — Isolation, evidence completeness, cost estimation

| # | Task | Done when |
| --- | --- | --- |
| 2.4.1 | Per-run containment identity | Unique network, volume, and container names per run. |
| 2.4.2 | Cross-run leak test | Fails if any run observes another run's state. |
| 2.4.3 | Evidence-completeness metric | Computed over required fields by a tested metric — with a test that fails when the metric is faked, per the `corpus_metrics` rule. |
| 2.4.4 | Pre-run resource estimate | Requests, wall time, browser contexts, records touched; actual-vs-estimate delta recorded in the run summary. |

### WP2.5 — CI, decision records, acceptance

- New `.github/workflows/phase2.yml` with a deterministic lane and a container/browser lane.
  `phase0.yml` and `phase1.yml` are not edited.
- `make phase2-check` and `make phase2-demo`, following the existing naming.
- ADRs: browser adapter authorization model; persistent-fixture reset strategy; manifest-derived
  resource ownership (§3.3).
- Any code executing only in the container lane is named as a coverage exclusion in the acceptance
  record, the way `relay.py` was.
- `docs/phase2-acceptance.md` with measured results, defects found during acceptance, and known
  limits.

---

## 5. Test plan

- **Unit** — Manifest 1.2 and Scenario 1.2 conversion; browser step compilation and rejection of
  free-form JS, arbitrary URLs, and arbitrary selectors; snapshot-hash canonicalization over
  ordered result sets; defense-profile applicability; evidence-completeness metric.
- **Property** — mutations of host, origin, org, resource, method, arguments, role, credential
  handle, redirect, subresource origin, and side-effect class. Every unauthorized mutation denied
  before any adapter I/O, including before the browser opens a context.
- **Contract** — the browser adapter runs the same shared adapter suite as HTTP and tool adapters.
  No exemptions; if a requirement genuinely cannot apply to a browser, that is an ADR, not a skip.
- **Integration** — full paired loops per scenario on both surfaces, with equal seed hashes, valid
  evidence chains, bounded shared budgets, passing clean tasks, and harness policy outcomes
  recorded separately from application security outcomes.
- **Fault injection** — failure and cancellation injected at every lifecycle stage in both raising
  and cancelled forms, now including database-unavailable, reset-failed, snapshot-mismatch, and
  browser-crashed. Every case must tear down and leave a verifiable partial bundle or an explicit
  evidence-integrity incident.
- **Isolation** — 100 consecutive runs, cross-run leak detection, egress refused, control plane
  rejects a customer credential, database unreachable from the attack credential.
- **Regression** — Phase 0's 57 tests and Phase 1's 133 tests pass unchanged, byte-identical
  digests for existing manifests and ledgers.

---

## 6. Acceptance checkpoint

Each number below names how it is measured. Nothing here is established by inspection or inferred
from a successful implementation.

| Checkpoint | Threshold | Measurement |
| --- | --- | --- |
| Isolated consecutive runs | 100, no cross-run state leakage | Scripted loop; every failure reported, never rerun until clean. |
| Unintended cross-tenant access by the harness | 0 | Observed across the integration suite. |
| Evidence-field completeness | ≥ 99% | Tested metric over required fields. |
| Cross-surface oracle agreement | Every shared workflow agrees | Per-scenario report; disagreements listed, not averaged. |
| Resource use vs pre-run estimate | ±10% | Requests, wall time, browser contexts. Token/API cost is Phase 3 — Phase 2 has no real model calls. |
| Seeded recall | ≥ 90% | `corpus_metrics` over explicit ground-truth labels. |
| False positives | ≤ 5% | Same, over defended negative controls. |
| API-lane replay | ≥ 95% | Normalized event and oracle hashes; no trial excluded. |
| Browser-lane replay | Reported separately | Own number, own stated reason for any gap. |
| Browser emergency stop | Measured and reported | Separate from Phase 0's in-process p99; a browser is an out-of-process child. |
| Prior suites | 57 + 133 passing, unchanged | Existing lanes. |
| Coverage | ≥ 85% branch | Floor, not target. |

---

## 7. Risks

| Risk | Impact | Mitigation |
| --- | --- | --- |
| Postgres non-determinism leaks into scored output | Replay rate collapses; the project's core claim weakens | §2.1 mitigations, each enforced by a test rather than a convention. |
| Browser flake read as a security signal | False findings; corpus metrics become meaningless | Scored output from state and typed DOM assertions only; browser replay reported separately. |
| Resource-ownership map (§3.3) gets solved by asking the fixture | Kernel starts trusting the component under test — a genuine trust-boundary regression | Ownership resolved from signed manifest data only; the fixture's opinion is observed data for the oracle. |
| Scope: `supportlab` + Postgres + Playwright + 20 scenarios in one phase | The phase stalls half-done | WP2.1 and WP2.2 are independent after §3 lands and can proceed in parallel; WP2.3 needs both. |
| Reset cost per leg at 100-run scale | Isolation checkpoint becomes impractically slow | Template-database reset; measure per-leg reset time early and revisit before authoring 20 scenarios. |
| Coverage dilution from container-only browser code | The 85% floor is met on paper | Name exclusions explicitly in the acceptance record, as `relay.py` was. |

---

## 8. Sequencing

```
WP2.0 (debt)
   └─> §3 contracts (Manifest 1.2, Scenario 1.2, ownership, browser action types)
          ├─> WP2.1 supportlab ──┐
          └─> WP2.2 browser ─────┴─> WP2.3 corpus ─> WP2.4 isolation/evidence/cost ─> WP2.5 CI + acceptance
```

WP2.0 is a prerequisite for trusting any Phase 2 measurement. The §3 contract work is a
prerequisite for both build streams and should land as one reviewed change. WP2.1 and WP2.2 are
independent of each other and can run in parallel. WP2.3 needs both surfaces working. WP2.4 needs
the corpus in place to have something to run 100 times.

---

## 9. Open questions

These need a decision before the work package that depends on them starts. Recommendations given;
each becomes an ADR.

1. **Reset strategy** — template database (recommended, §2.1) versus per-leg transactional
   rollback. Blocks WP2.1.
2. **Resource-ownership encoding** — signed explicit ID sets versus signed ranges tied to the seed.
   Ranges scale better; explicit sets are simpler to audit. Blocks §3.3 and therefore both build
   streams.
3. **Browser lane in the PR path** — recommendation is no: keep the PR lane deterministic and fast,
   and run the browser lane in the container job, consistent with how Phase 1 split its lanes.
4. **Playwright browser pinning** — pin the browser build by revision alongside the Python
   package, otherwise "pinned replay" is not pinned. Recommendation: pin, and record the revision
   in every browser-lane event.
5. **Does SSRF need a second container?** A meaningful SSRF target needs somewhere to point. A
   second internal-only container on the isolated network is the safe answer; confirm it does not
   compromise the no-egress posture before authoring those scenarios.
