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
