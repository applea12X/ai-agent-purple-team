# Phase 0 Threat Model

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

## Residual risk and Phase 0 limits

Phase 0 adapters are trusted. A malicious or incorrectly implemented future network adapter could
perform I/O without calling the target guard; adapter conformance and isolation remain mandatory.
The local ledger anchor is tamper-evident against unsynchronized changes, not immutable against an
attacker who can rewrite both ledger and anchor. Cancellation guarantees cover cooperative
asyncio work, not an uncontrolled external process. Phase 0 supports no production target, live
model, browser, write, remediation, or arbitrary network operation.
