# Threat Model

## Assets and security objectives

- Signed authorization scope, validity, revocation status, and exact exclusions.
- Fixture tenant/resource boundaries and synthetic records.
- Credential values, canaries, offline model inputs, and evidence.
- Budget, cancellation, policy, and replay integrity.

The kernel must prevent unapproved I/O, cross-tenant/resource access, credential disclosure,
unbounded activity, evidence corruption going unnoticed, and nondeterministic replay claims.

## Attacker capabilities

The attacker may control every action field, URL encoding, tenant/resource identifier, target
response, redirect location, model response, and adapter result. It may trigger races, policy or
revocation outages, budget exhaustion, partial evidence writes, exceptions containing secrets,
DNS drift, and repeated or reordered redirect observations. The attacker cannot alter trusted
public keys, tool definitions, kernel code, or the configured adapter IP observations without
that adapter itself becoming compromised.

## Controls

| Threat | Phase 0 control |
| --- | --- |
| Scope or confused-deputy attack | Exact signed assets, trusted tool/path binding, tenant/resource checks, exclusions |
| DNS rebinding or SSRF | Adapter-observed non-empty DNS evidence and exact IP allowlists |
| Redirect escape | Manual consecutive hop authorization bound to the original asset/tool/resource |
| Authorization changes during work | Signature, time, revocation, and policy revalidation at action/hop boundaries |
| Runaway or post-kill work | Atomic task ownership, cancellation wait, hard budgets, wall-time deadline |
| Credential/canary disclosure | Opaque handles and runtime registration/redaction of resolved secrets |
| Evidence mutation | Canonical hash chain, atomic sequencing, fsync, and final anchor verification |
| Replay overclaim | Separate semantic event and deterministic score hashes |
| Live-model nondeterminism/egress | Exact offline fixture lookup with no network fallback |

## Phase 1 additions

Phase 1 keeps every control above and adds a closed evaluation loop around the same per-action
boundary. The new assets are the fixture control plane, the seeded state and its snapshot hashes,
the defense registry, and the report bundle. The attacker additionally controls chat output,
retrieved fixture content, tool-intent text, argument values, and idempotency keys.

| Threat | Phase 1 control |
| --- | --- |
| Write escalation beyond the fixture | Manifest 1.0 stays read-only; 1.1 grants only exact registered synthetic operations; `DESTRUCTIVE` always denied |
| Direct or indirect prompt injection | Model and retrieved content are untrusted data; intents are compiled into typed actions and re-authorized before execution |
| Planner-supplied code or egress | Plans are typed DAG data with no code, shell, URL, or browser fields, bounded by manifest node/depth limits |
| Control-plane abuse by an attack credential | Separately scoped control credentials; a customer credential on a control route is rejected |
| Fixture escape or external egress | Read-only root, tmpfs state, dropped capabilities, `no-new-privileges`, internal-only network |
| Adapter self-selection | Immutable registry keyed by exact adapter and operation; duplicate keys fail startup |
| Duplicate or replayed writes | Registered idempotency keys return the original outcome without repeating the effect |
| Unverifiable or partial evidence | Bundle inventory, digests, ledger links, and an explicit evidence-integrity incident when the ledger breaks |
| Overclaimed mitigation | A defense is credited only when the seeded attack succeeds in the baseline and fails on replay under the same seed, plan, and budget |
| Nondeterministic canonical bytes | Set-derived arrays are sorted before canonicalization, so digests and signatures do not depend on iteration order |

## Residual risk and current limits

Adapters are trusted. A malicious or incorrectly implemented network adapter could perform I/O
without calling the target guard; adapter conformance and isolation remain mandatory. The local
ledger anchor is tamper-evident against unsynchronized changes, not immutable against an attacker
who can rewrite both ledger and anchor. Cancellation guarantees cover cooperative asyncio work,
not an uncontrolled external process.

Writes are limited to exact registered operations on the synthetic local fixture. There is still
no production target, live model, browser, autonomous source remediation, or arbitrary network
operation. The host-side ingress relay is trusted plumbing: it holds no fixture credentials and
has a fixed forwarding destination, but it does terminate loopback connections outside the
isolated network. Detection times are logical ticks, not production latency, and a passing run is
evidence about these exact fixtures, seeds, and defenses only.

## Phase 2 additions

Phase 2 keeps every control above and adds a persistent multi-organization application and a browser
surface around the same per-action boundary. The new assets are the seeded database and its
snapshot hashes, the signed resource-ownership map, the per-run database credential, the internal
upstream, and the browser trace/screenshot artifacts. The attacker additionally controls the
browser DOM content, subresource requests the page attempts, the upstream payloads a scenario
consumes, and the arguments to registered UI flows.

| Threat | Phase 2 control |
| --- | --- |
| Confused-deputy ownership across a seeded database | Ownership resolved from the signed manifest only; an unsigned resource or an owner/tenant mismatch is denied before I/O; the fixture's opinion is observed data for the oracle |
| Database reached by an attack credential | PostgreSQL on the internal network with no published ports and a per-run credential scope that no attack credential can reference; a manifest that names it as an attack handle fails validation |
| Nondeterminism leaking from a real database | Total query ordering, seed-derived identifiers, banned `now()`/`random()`/`gen_random_uuid()`, and a canonical ordered snapshot hash — each enforced by a test; template reset verified by hash equality |
| Planner-supplied browser code or navigation | Typed navigate/fill/click/read steps from a signed flow registry; free-form JavaScript, URLs, and selectors rejected at compile time |
| Browser reaching an unauthorized origin | Every navigation, redirect, and subresource origin authorized before the request; unauthorized origins aborted at the routing layer, recorded as policy denials, and charged to the budget |
| SSRF and unsafe upstream consumption | The only upstream path is a code-mapped destination; an internal metadata target and a tampered feed are registered flaws whose defended pair is an allowlist or a strict schema |
| Browser flake read as a security signal | Scored output from application state and typed DOM assertions only; browser-lane replay reported separately from the API lane |
| Out-of-process browser after a stop | The browser child is killed in the adapter's `finally` path on completion, failure, timeout, budget exhaustion, or cancellation; emergency stop measured separately |

Residual risk is unchanged in kind from Phase 1: adapters remain trusted, the ledger anchor is
tamper-evident rather than immutable, and a passing run is evidence about these exact fixtures,
seeds, and defenses only. The browser adds an out-of-process dependency whose bit-level determinism
is explicitly not claimed; its replay rate is reported on its own.

## Phase 3 and Phase 4 additions

Added in Phase 5 (loose-ends audit, `docs/phase5/loose-ends.md`). Until then this file stopped
at Phase 2. The controls themselves are not new. Each row names the decision record or test
where it already lives. Phase 3 adds a model plane, a RAG agent, an adaptive attacker, and a
judge. Phase 4 adds release machinery and CI gates. The new assets are the signed model origin
and its credential handle, retrieved chunks and their provenance, the agent's memory, the frozen
evaluator labels, the committed gate baselines, and the run attestations. The attacker
additionally controls model output (fully, in the captured-model case), retrieved content in
nine channels, and the text a judge reads.

| Threat | Phase 3–4 control |
| --- | --- |
| A model endpoint used to reach the target, or a rebind onto it | Model origins are a separate signed plane, disjoint from every target asset by schema; `SafetyRuntime.authorize_model` refuses a resolution that lands on a signed target endpoint; no plan can address the model ([ADR 0008](adr/0008-model-plane-separate-from-target-plane.md), `tests/phase3/test_model_plane.py`) |
| A captured model emits out-of-scope or invented actions | Intents are typed, validated against their argument models, compiled from a closed vocabulary, and capped per turn; an invented operation is a recorded refusal (`tests/phase3/test_compromised_model.py`, stand-in model only) |
| Indirect injection through retrieved content | Every chunk carries source and trust level into evidence; `retrieval-provenance-guard` delimits untrusted content and, since `f20f482`, the email sink itself refuses after an untrusted retrieval |
| An advisory component deciding a binding verdict | `VerdictProvenance` is required on every scored artifact and `require_binding()` guards run status, mitigation credit, and corpus metrics; attacker probes run after every binding measurement ([ADR 0009](adr/0009-advisory-versus-binding-verdicts.md) and its amendment) |
| Evidence-borne injection against the judge | Typed, bounded, delimited judge input; citations validated; abstention is a valid outcome; verdicts advisory ([ADR 0010](adr/0010-judge-input-and-abstention.md)) |
| Model credential disclosure | Broker-held handle, absent from model context and from evidence; the stub-transport tests check the header carries it and the record does not |
| Cost or token runaway | Token and cost charged to the signed budget; a cap breach ends the run fail-closed with a budget outcome |
| A real-model or advisory result turning CI red or green | Gates read deterministic verdicts only, rejected by type at the gate boundary ([ADR 0013](adr/0013-enforcing-gates.md)) |
| A tampered bundle presented as a release | Ed25519/JCS run attestation over code, lockfile, corpus, manifests, and pins, verified offline ([ADR 0012](adr/0012-run-attestation-format.md)) |
| Tuning against the held-out set | The holdout is digest-pinned, and a grep test keeps every module except its executor from reading it |
| A credential reaching committed samples | `tests/phase4/test_sample_hygiene.py` scans `docs/samples/` for credential fields, token shapes, canaries, and keys, and is tested against planted leaks |

Residual risk added by these phases: the real-model evidence is one scenario on one local model
(Phase 4, WP4.0.1). Email is the only sink gated by retrieval provenance, and the taint is per
actor and per most recent run, not full information flow. Retrieval is lexical
([ADR 0011](adr/0011-deterministic-retrieval-without-embeddings.md)). There is no
code-execution surface, so unexpected code execution is covered only as a containment property.
The only release attestation so far used an ephemeral key.

## Phase 5 additions: runaway loops

| Threat | Phase 5 control |
| --- | --- |
| A captured or confused model, or a model-driven attacker, spends its caps and budget repeating the same action | Kernel-side action-state hashing at every action boundary, compile-time refusals included. The N-th repetition is refused before dispatch, and K consecutive no-progress actions end the run `RUNAWAY_LOOP_DETECTED`. The guard latches, so the kernel refuses everything after a trip, and teardown still runs. Armed only by signed thresholds (`phase5.loop_guard`, `EvaluationMatrix.loop_guard`) ([ADR 0018](adr/0018-runaway-loop-detection.md), `tests/phase5/test_runaway_loop.py`) |

Residual risk: the detector is disarmed unless the engagement signs thresholds, so manifests
1.0–1.4 keep only the structural bounds above. A target that answers each repeated read with new bytes
defeats both checks. Shadow mode over-approximates repetition and does not evaluate no-progress.
